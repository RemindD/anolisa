'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const PROFILE = 'sqlite_maintenance_gate';
const SOURCE = 'src/agent-sec-core/v2/crates/asc-sqlite-kernel/src/maintenance.rs';
const IMAGE = 'rust:1.88-bookworm';
const CASES = ['nan_marker', 'expired_finite_marker', 'recent_finite_marker', 'unparseable_marker'];
const hash = (value) => crypto.createHash('sha256').update(value).digest('hex');
const read = (file) => JSON.parse(fs.readFileSync(file, 'utf8'));
const write = (file, value) => fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);

function check(condition, message) {
  if (!condition) throw new Error(message);
}

function validatePlan(analysis) {
  const plan = analysis.poc;
  check(plan && typeof plan.reason === 'string' && plan.reason.trim() && plan.reason.length <= 500,
    'PoC selection requires a short applicability reason');
  if (plan.profile === null) {
    check(plan.case === null && plan.expected_outcome === null, 'An unsupported PoC must not select a case or outcome');
    return;
  }
  check(plan.profile === PROFILE && CASES.slice(0, 2).includes(plan.case), 'Unknown approved PoC profile or case');
  check(['Ran', 'NotDue'].includes(plan.expected_outcome), 'PoC requires an expected component outcome');
  check(analysis.disposition === 'active' && ['in_scope', 'partially_in_scope'].includes(analysis.scope.status) &&
    analysis.evidence.some((item) => item.path === SOURCE), 'PoC needs an active in-scope maintenance claim and source evidence');
}

function containerArguments(source, name) {
  return ['run', '--detach', '--name', name, '--network=bridge', '--user=1000:1000', '--read-only', '--cap-drop=ALL',
    '--security-opt=no-new-privileges', '--memory=4g', '--memory-swap=4g', '--cpus=2', '--pids-limit=256',
    '--tmpfs', '/work:rw,exec,nosuid,size=2g,uid=1000,gid=1000,mode=700',
    '--tmpfs', '/tmp:rw,noexec,nosuid,size=128m,uid=1000,gid=1000,mode=700',
    '--mount', `type=bind,src=${source},dst=/source,readonly`, '--workdir=/work',
    '--env=CARGO_HOME=/work/cargo', '--env=CARGO_TARGET_DIR=/work/target', '--env=CARGO_BUILD_JOBS=2',
    '--env=TMPDIR=/work', IMAGE, 'sleep', '900'];
}

function observations(stdout) {
  const rows = stdout.split('\n').filter((line) => line.startsWith('TRIAGE_CASE '))
    .map((line) => JSON.parse(line.slice('TRIAGE_CASE '.length)));
  check(rows.length === CASES.length && new Set(rows.map((row) => row.id)).size === CASES.length &&
    CASES.every((id) => rows.some((row) => row.id === id)), 'PoC did not record all four unique cases');
  for (const row of rows) {
    check((row.outcome === 'Ran' && row.callback_calls === 1) ||
      (row.outcome === 'NotDue' && row.callback_calls === 0), 'Inconsistent callback observation');
    if (row.id !== 'nan_marker') check(row.outcome === (row.id === 'recent_finite_marker' ? 'NotDue' : 'Ran'),
      'PoC control failed');
  }
  return rows;
}

function runPoc(root) {
  const analysis = read(path.join(root, 'input/analysis.json'));
  validatePlan(analysis);
  const result = {
    source_commit_sha: analysis.source_commit_sha, profile: analysis.poc.profile, selected_case: analysis.poc.case,
    status: 'not_executed', reason: analysis.poc.reason, success_semantics: 'not_applicable',
    started_at_utc: new Date().toISOString(), commands: [], logs: [], cases: [],
    limits: { build_timeout_seconds: 300, baseline_timeout_seconds: 60, poc_timeout_seconds: 30,
      memory_mib: 4096, cpus: 2, pids: 256, work_storage_mib: 2048, temporary_storage_mib: 128 },
    network: 'Build may download locked dependencies; tests require all external networks disconnected.',
    does_not_establish: 'Component behavior only; no daemon/CLI integration, database growth, or production impact was tested.',
    cleanup_result: 'not_needed',
  };
  let name;
  let source;
  // The Docker client and container receive no inherited model or GitHub credentials.
  const docker = (args, timeout = 15_000) => spawnSync('docker', args, {
    encoding: 'utf8', env: { PATH: process.env.PATH }, timeout, maxBuffer: 4 * 1024 * 1024,
  });
  const command = (label, args, timeout) => {
    const started = Date.now();
    const packet = docker(args, timeout);
    const file = `poc-${label}.log`;
    const log = `${packet.stdout || ''}\n${packet.stderr || ''}`;
    fs.writeFileSync(path.join(root, 'output', file), log);
    result.logs.push({ path: file, sha256: hash(log) });
    result.commands.push({ argv: ['docker', ...args], cwd: '/work', exit_code: packet.status,
      error: packet.error?.code || null, elapsed_seconds: (Date.now() - started) / 1000 });
    check(!packet.error && packet.status === 0,
      `${label} ${packet.error?.code || `exited ${packet.status}`}; see ${file}`);
    return packet.stdout;
  };
  try {
    if (analysis.poc.profile !== null) {
      result.status = 'blocked';
      source = fs.mkdtempSync(path.join(root, 'poc-source-'));
      fs.cpSync(path.join(root, 'source/src/agent-sec-core/v2'), source, { recursive: true });
      fs.chmodSync(source, 0o755);
      const harness = fs.readFileSync(path.join(__dirname, '../issue-analysis/poc/sqlite-maintenance.rs'));
      const testFile = path.join(source, 'crates/asc-sqlite-kernel/tests/issue_triage_maintenance.rs');
      check(!fs.existsSync(testFile), 'Frozen source already contains the reserved PoC harness name');
      fs.mkdirSync(path.dirname(testFile), { recursive: true });
      fs.writeFileSync(testFile, harness);
      fs.writeFileSync(path.join(root, 'output/poc-harness.rs'), harness);
      result.harness_sha256 = hash(harness);
      result.lockfile_sha256 = hash(fs.readFileSync(path.join(source, 'Cargo.lock')));
      result.product_source_sha256 = hash(fs.readFileSync(path.join(source, 'crates/asc-sqlite-kernel/src/maintenance.rs')));
      name = `sec-core-issue-poc-${crypto.randomUUID()}`;
      command('container', containerArguments(source, name), 180_000);
      result.image = { requested: IMAGE, id: command('image', ['inspect', '--format={{.Image}}', name]).trim() };
      result.toolchain = command('toolchain', ['exec', name, 'rustc', '--version']).trim();
      const build = command('build', ['exec', name, 'cargo', 'test', '--locked', '--manifest-path', '/source/Cargo.toml',
        '-p', 'asc-sqlite-kernel', '--lib', '--test', 'issue_triage_maintenance', '--no-run', '--message-format=json'], 300_000);
      const artifacts = build.split('\n').filter((line) => line.startsWith('{')).map(JSON.parse)
        .filter((item) => item.reason === 'compiler-artifact' && item.profile?.test && item.executable);
      const executable = (target) => {
        const files = artifacts.filter((item) => item.target.name === target);
        check(files.length === 1 && /^\/work\/target\/[\w./-]+$/.test(files[0].executable) &&
          !files[0].executable.includes('..'), `Missing or invalid executable for ${target}`);
        return files[0].executable;
      };
      command('disconnect', ['network', 'disconnect', 'bridge', name]);
      check(command('network', ['inspect', '--format={{json .NetworkSettings.Networks}}', name]).trim() === '{}',
        'Cannot confirm network isolation; no tests executed');
      result.network = 'Locked dependency build completed; baseline and PoC ran with no external network attachment.';
      const baseline = command('baseline', ['exec', name, executable('asc_sqlite_kernel'), '--test-threads=1'], 60_000);
      check(/test result: ok\. [1-9]\d* passed/.test(baseline), 'Baseline did not report passing tests');
      result.baseline = 'passed';
      result.status = 'failed';
      const poc = command('cases', ['exec', name, executable('issue_triage_maintenance'), '--test-threads=1', '--nocapture'], 30_000);
      check(/test result: ok\. 4 passed/.test(poc), 'PoC did not complete four checks');
      result.cases = observations(poc);
      const selected = result.cases.find((row) => row.id === result.selected_case);
      result.status = 'executed';
      result.success_semantics = selected.outcome === 'NotDue' ? 'reproduction_confirmed' :
        result.selected_case === 'expired_finite_marker' ? 'claim_refuted' : 'contract_satisfied';
      result.reason = `${result.selected_case}: ${selected.outcome}, callback called ${selected.callback_calls} time(s); all three controls passed.`;
    }
  } catch (error) {
    result.reason = error.message;
  } finally {
    if (name) {
      const cleanup = docker(['rm', '--force', name]);
      result.cleanup_result = cleanup.status === 0 ? 'container_removed' : 'container_removal_failed';
      if (cleanup.status !== 0) {
        result.status = 'blocked';
        result.reason += ' Container cleanup could not be confirmed.';
      }
    }
    if (source) fs.rmSync(source, { recursive: true, force: true });
    result.finished_at_utc = new Date().toISOString();
    write(path.join(root, 'input/poc.json'), result);
    write(path.join(root, 'output/poc.json'), result);
  }
  return result;
}

module.exports = { PROFILE, SOURCE, validatePlan, containerArguments, observations, runPoc };
if (require.main === module) console.log(JSON.stringify(runPoc(process.argv[2]), null, 2));
