#!/usr/bin/env node
import { spawn } from "node:child_process";
import { accessSync, constants as fsConstants, createWriteStream } from "node:fs";
import fs from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  PLUGIN_ID,
  extractVersion,
  findFreePort,
  parseJsonFromOutput,
  redactArgs,
  sleep,
  slugify,
  withTimeout,
} from "./pilot/common.mjs";
import { StepError, formatError, serializeError } from "./pilot/errors.mjs";
import {
  assertGatewayTrafficProbe,
  assertPolicyMatrix,
  runGatewayPolicyMatrix,
  runGatewayTrafficProbe,
} from "./pilot/gateway-probes.mjs";
import { assertHookProbe, runHookProbe } from "./pilot/hook-probe.mjs";
import {
  configureGatewayPilotModel,
  startMockModelServer,
} from "./pilot/mock-model.mjs";
import { buildAgentSecCliOverrideConfig, installWrappers } from "./pilot/wrappers.mjs";

// This file is intentionally kept as the top-level orchestration script. The
// heavier test mechanics live under ./pilot so the acceptance flow is readable:
// prepare isolated state, deploy, start Gateway, run probes, write evidence.
const SCRIPT_DIR = path.dirname(fileURLToPath(import.meta.url));
const PLUGIN_ROOT = path.resolve(SCRIPT_DIR, "..", "..");
const REPO_ROOT = path.resolve(PLUGIN_ROOT, "..");
const AGENT_SEC_CLI_PROJECT = path.join(REPO_ROOT, "agent-sec-cli");
const DEFAULT_COMMAND_TIMEOUT_MS = 600_000;
const DEFAULT_GATEWAY_TIMEOUT_MS = 180_000;
const args = parseArgs(process.argv.slice(2));
const startedProcesses = [];
const startedServers = [];

// Every step writes logs under workdir/logs and a compact reference here. The
// final pilot-result.json is the contract consumed by manual review and matrix
// task evidence, so keep it stable and append-only when possible.
const result = {
  schemaVersion: 1,
  task: "PILOT-LATEST-OPENCLAW-E2E",
  status: "running",
  startedAt: new Date().toISOString(),
  finishedAt: undefined,
  repoRoot: REPO_ROOT,
  pluginRoot: PLUGIN_ROOT,
  workdir: undefined,
  artifactsDir: undefined,
  logsDir: undefined,
  versions: {},
  paths: {},
  steps: [],
  daemonHealth: undefined,
  gatewayHealth: undefined,
  install: {},
  mockModel: undefined,
  runtimeInspect: undefined,
  gatewayTrafficProbe: undefined,
  policyMatrix: undefined,
  hookProbe: undefined,
  errors: [],
};

try {
  await runPilot();
  result.status = "passed";
} catch (error) {
  result.status = "failed";
  result.errors.push(serializeError(error));
  console.error(formatError(error));
  process.exitCode = 1;
} finally {
  await stopAllProcesses();
  result.finishedAt = new Date().toISOString();
  await writeResultFile();
}

async function runPilot() {
  if (args.help) {
    printHelp();
    process.exit(0);
  }

  const workdir = args.workdir
    ? path.resolve(args.workdir)
    : process.env.AGENT_SEC_OPENCLAW_PILOT_WORKDIR
      ? path.resolve(process.env.AGENT_SEC_OPENCLAW_PILOT_WORKDIR)
      : await fs.mkdtemp(path.join(os.tmpdir(), "agentsec-openclaw-pilot-"));
  const logsDir = path.join(workdir, "logs");
  const artifactsDir = path.join(workdir, "artifacts");
  const binDir = path.join(workdir, "bin");
  const openclawStateDir = path.join(workdir, "openclaw-state");
  const dataDir = path.join(workdir, "agent-sec-data");
  const xdgDataHome = path.join(workdir, "xdg-data");
  const xdgConfigHome = path.join(workdir, "xdg-config");
  const xdgCacheHome = path.join(workdir, "xdg-cache");
  const daemonSocket = path.join(workdir, "agent-sec-daemon.sock");
  const openclawConfigPath = path.join(openclawStateDir, "openclaw.json");
  const agentSecCliCallsLog = path.join(logsDir, "agent-sec-cli-calls.jsonl");
  const agentSecCliOverrideFile = path.join(workdir, "agent-sec-cli-overrides.json");

  result.workdir = workdir;
  result.artifactsDir = artifactsDir;
  result.logsDir = logsDir;
  result.paths = {
    binDir,
    openclawStateDir,
    openclawConfigPath,
    daemonSocket,
    dataDir,
    xdgDataHome,
    xdgConfigHome,
    xdgCacheHome,
    agentSecCliCallsLog,
    agentSecCliOverrideFile,
  };

  await fs.mkdir(logsDir, { recursive: true });
  await fs.mkdir(artifactsDir, { recursive: true });
  await fs.mkdir(binDir, { recursive: true });
  await fs.mkdir(openclawStateDir, { recursive: true });
  await fs.mkdir(dataDir, { recursive: true });
  await fs.mkdir(xdgDataHome, { recursive: true });
  await fs.mkdir(xdgConfigHome, { recursive: true });
  await fs.mkdir(xdgCacheHome, { recursive: true });
  await fs.writeFile(agentSecCliCallsLog, "");
  await fs.writeFile(
    agentSecCliOverrideFile,
    `${JSON.stringify(buildAgentSecCliOverrideConfig(), null, 2)}\n`,
  );

  // The wrappers make the test hermetic without hiding the real host behavior:
  // openclaw still comes from PATH/--openclaw-bin, while agent-sec-cli calls are
  // logged and only policy-marker inputs get deterministic deny overrides.
  const wrapperTargets = await installWrappers({
    agentSecCliProject: AGENT_SEC_CLI_PROJECT,
    binDir,
    openclawBin: resolveOpenClawBin(args.openclawBin),
    agentSecCliBin: args.agentSecCli,
    agentSecDaemonBin: args.agentSecDaemon,
    pluginRoot: PLUGIN_ROOT,
    repoRoot: REPO_ROOT,
  });
  result.paths.agentSecCliLauncher = wrapperTargets.agentSecCli;
  result.paths.agentSecDaemonLauncher = wrapperTargets.agentSecDaemon;

  const baseEnv = {
    ...process.env,
    PATH: `${binDir}${path.delimiter}${process.env.PATH ?? ""}`,
    OPENCLAW_STATE_DIR: openclawStateDir,
    OPENCLAW_CONFIG_PATH: openclawConfigPath,
    AGENT_SEC_DAEMON_SOCKET: daemonSocket,
    AGENT_SEC_DATA_DIR: dataDir,
    AGENT_SEC_OPENCLAW_PILOT_CLI_LOG: agentSecCliCallsLog,
    AGENT_SEC_OPENCLAW_PILOT_CLI_OVERRIDE_FILE: agentSecCliOverrideFile,
    XDG_DATA_HOME: xdgDataHome,
    XDG_CONFIG_HOME: xdgConfigHome,
    XDG_CACHE_HOME: xdgCacheHome,
    NO_COLOR: "1",
  };

  result.versions.node = process.version;
  await runRequiredStep("npm-version", "npm", ["--version"], { cwd: PLUGIN_ROOT, env: baseEnv });
  const openclawVersion = await runRequiredStep("openclaw-version", "openclaw", ["--version"], {
    cwd: PLUGIN_ROOT,
    env: baseEnv,
  });
  result.versions.openclaw = extractVersion(openclawVersion.stdout) ?? openclawVersion.stdout.trim();

  const agentSecVersion = await runRequiredStep(
    "agent-sec-cli-version",
    "agent-sec-cli",
    ["--version"],
    { cwd: REPO_ROOT, env: baseEnv },
  );
  result.versions.agentSecCli = agentSecVersion.stdout.trim();

  await runRequiredStep("agent-sec-plugin-build", "npm", ["run", "build"], {
    cwd: PLUGIN_ROOT,
    env: baseEnv,
    timeoutMs: DEFAULT_COMMAND_TIMEOUT_MS,
  });
  const packResult = await runRequiredStep(
    "agent-sec-plugin-pack",
    "npm",
    ["pack", "--pack-destination", artifactsDir, "--json"],
    { cwd: PLUGIN_ROOT, env: baseEnv, timeoutMs: DEFAULT_COMMAND_TIMEOUT_MS },
  );
  result.install.packageArtifact = parseNpmPackArtifact(packResult.stdout, artifactsDir);

  const daemon = startProcess("agent-sec-daemon", "agent-sec-daemon", ["serve", "--socket", daemonSocket], {
    cwd: REPO_ROOT,
    env: baseEnv,
  });
  result.daemonHealth = await waitForDaemonHealth(daemonSocket, {
    processRef: daemon,
    timeoutMs: 30_000,
  });

  await runRequiredStep("jq-version", "jq", ["--version"], { cwd: PLUGIN_ROOT, env: baseEnv });
  const deployResult = await runRequiredStep(
    "openclaw-plugin-deploy",
    "bash",
    [path.join(PLUGIN_ROOT, "scripts", "deploy.sh"), PLUGIN_ROOT],
    { cwd: PLUGIN_ROOT, env: baseEnv, timeoutMs: DEFAULT_COMMAND_TIMEOUT_MS },
  );
  result.install.deployStdoutLog = deployResult.stdoutLog;
  result.install.deployStderrLog = deployResult.stderrLog;
  result.install.usedUnsafeInstallFlag =
    deployResult.stdout.includes("--dangerously-force-unsafe-install") ||
    deployResult.stderr.includes("--dangerously-force-unsafe-install");

  await runRequiredStep(
    "openclaw-config-enable-prompt-block",
    "openclaw",
    [
      "config",
      "set",
      "plugins.entries.agent-sec.config.promptScanBlock",
      "true",
      "--strict-json",
    ],
    { cwd: PLUGIN_ROOT, env: baseEnv },
  );
  await runRequiredStep(
    "openclaw-config-enable-code-approval",
    "openclaw",
    [
      "config",
      "set",
      "plugins.entries.agent-sec.config.codeScanRequireApproval",
      "true",
      "--strict-json",
    ],
    { cwd: PLUGIN_ROOT, env: baseEnv },
  );
  await runRequiredStep(
    "openclaw-config-enable-pii-block",
    "openclaw",
    [
      "config",
      "set",
      "plugins.entries.agent-sec.config.capabilities.pii-scan-user-input.enableBlock",
      "true",
      "--strict-json",
    ],
    { cwd: PLUGIN_ROOT, env: baseEnv },
  );
  await runRequiredStep(
    "openclaw-config-skill-ledger-warn",
    "openclaw",
    [
      "config",
      "set",
      "plugins.entries.agent-sec.config.capabilities.skill-ledger.policy",
      '"warn"',
      "--strict-json",
    ],
    { cwd: PLUGIN_ROOT, env: baseEnv },
  );

  const mockModel = await startMockModelServer({
    logsDir,
    registerServer: (serverRef) => startedServers.push(serverRef),
  });
  result.paths.mockModelBaseUrl = mockModel.baseUrl;
  result.mockModel = {
    baseUrl: mockModel.baseUrl,
    requestsLog: mockModel.requestsLog,
  };
  await configureGatewayPilotModel({
    env: baseEnv,
    mockModel,
    pluginRoot: PLUGIN_ROOT,
    runRequiredStep,
  });

  const gatewayPort = args.port ? Number(args.port) : await findFreePort();
  const gatewayUrl = `ws://127.0.0.1:${gatewayPort}`;
  result.paths.gatewayUrl = gatewayUrl;
  let gatewayToken;
  let gatewayProcess;
  const restartGateway = async (reason) => {
    if (gatewayProcess) {
      await stopStartedProcess(gatewayProcess);
    }
    // Policy config changes are applied before each matrix case. Restarting the
    // Gateway gives every case a fresh plugin runtime with the requested config.
    const started = await startOpenClawGateway({
      env: baseEnv,
      gatewayPort,
      gatewayToken,
      gatewayTimeoutMs: Number(args.gatewayTimeoutMs ?? DEFAULT_GATEWAY_TIMEOUT_MS),
      reason,
    });
    gatewayProcess = started.process;
    result.gatewayHealth = started.health;
    return gatewayProcess;
  };

  if (!args.skipGateway) {
    gatewayToken =
      args.gatewayToken ?? process.env.AGENT_SEC_OPENCLAW_PILOT_GATEWAY_TOKEN ?? "agent-sec-pilot-token";
    result.paths.gatewayAuth = "token";
    await restartGateway("initial");
  }

  const runtimeInspect = await runRequiredStep(
    "openclaw-plugin-runtime-inspect",
    "openclaw",
    ["plugins", "inspect", PLUGIN_ID, "--runtime", "--json"],
    { cwd: PLUGIN_ROOT, env: baseEnv, timeoutMs: DEFAULT_COMMAND_TIMEOUT_MS },
  );
  const runtimeInspectJson = parseJsonFromOutput(runtimeInspect.stdout);
  assertRuntimeLoaded(runtimeInspectJson);
  result.runtimeInspect = summarizeRuntimeInspect(runtimeInspectJson);
  result.runtimeInspect.rawLog = runtimeInspect.stdoutLog;

  if (!args.skipGateway) {
    result.gatewayTrafficProbe = await runGatewayTrafficProbe({
      assertProcessStillRunning,
      callGatewayRpc,
      dataDir,
      gatewayToken,
      gatewayUrl,
      logsDir,
      mockModel,
      processRef: gatewayProcess,
    });
    assertGatewayTrafficProbe(result.gatewayTrafficProbe);
    result.policyMatrix = await runGatewayPolicyMatrix({
      callGatewayRpc,
      cliLogPath: agentSecCliCallsLog,
      env: baseEnv,
      gatewayToken,
      gatewayUrl,
      mockModel,
      pluginRoot: PLUGIN_ROOT,
      restartGateway,
      runRequiredStep,
    });
    assertPolicyMatrix(result.policyMatrix);
  } else {
    result.gatewayTrafficProbe = {
      skipped: true,
      reason: "--skip-gateway",
    };
    result.policyMatrix = {
      skipped: true,
      reason: "--skip-gateway",
    };
  }

  result.hookProbe = await runHookProbe({
    env: baseEnv,
    logsDir,
    pluginRoot: PLUGIN_ROOT,
    repoRoot: REPO_ROOT,
    workdir,
    skipFailureProbes: args.skipFailureProbes,
  });

  assertHookProbe(result.hookProbe);
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--help" || arg === "-h") {
      parsed.help = true;
    } else if (arg === "--skip-gateway") {
      parsed.skipGateway = true;
    } else if (arg === "--skip-failure-probes") {
      parsed.skipFailureProbes = true;
    } else if (arg === "--workdir") {
      parsed.workdir = argv[++index];
    } else if (arg === "--openclaw-bin") {
      parsed.openclawBin = argv[++index];
    } else if (arg === "--agent-sec-cli") {
      parsed.agentSecCli = argv[++index];
    } else if (arg === "--agent-sec-daemon") {
      parsed.agentSecDaemon = argv[++index];
    } else if (arg === "--port") {
      parsed.port = argv[++index];
    } else if (arg === "--gateway-timeout-ms") {
      parsed.gatewayTimeoutMs = argv[++index];
    } else if (arg === "--gateway-token") {
      parsed.gatewayToken = argv[++index];
    } else {
      throw new Error(`unknown argument: ${arg}`);
    }
  }
  return parsed;
}

function printHelp() {
  console.log(`Usage: npm run e2e:latest-openclaw -- [options]

Options:
  --workdir <dir>              Keep all state, logs, and artifacts under dir.
  --openclaw-bin <path>        OpenClaw executable or openclaw.mjs path.
  --agent-sec-cli <path>       Installed agent-sec-cli binary.
  --agent-sec-daemon <path>    Installed agent-sec-daemon binary.
  --port <port>                Gateway port. Defaults to a free local port.
  --gateway-timeout-ms <ms>    Gateway health wait budget.
  --gateway-token <token>      Gateway token for local health checks.
  --skip-gateway               Install and inspect without starting gateway.
  --skip-failure-probes        Skip negative hook probes.
`);
}

function resolveOpenClawBin(cliArg) {
  if (cliArg) return resolveExecutableReference(cliArg) ?? path.resolve(cliArg);
  if (process.env.OPENCLAW_BIN) {
    const resolved = resolveExecutableReference(process.env.OPENCLAW_BIN);
    if (resolved) return resolved;
    throw new Error(`Unable to find OpenClaw executable from OPENCLAW_BIN=${process.env.OPENCLAW_BIN}`);
  }
  const openclaw = resolveExecutableFromPath("openclaw");
  if (!openclaw) {
    throw new Error("Unable to find OpenClaw executable. Install openclaw or pass --openclaw-bin/OPENCLAW_BIN.");
  }
  return openclaw;
}

function resolveExecutableReference(value) {
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  if (trimmed.includes(path.sep) || path.isAbsolute(trimmed)) {
    return path.resolve(trimmed);
  }
  return resolveExecutableFromPath(trimmed);
}

function resolveExecutableFromPath(command) {
  for (const dir of (process.env.PATH ?? "").split(path.delimiter)) {
    if (!dir) continue;
    const candidate = path.join(dir, command);
    if (isExecutable(candidate)) {
      return candidate;
    }
  }
  return undefined;
}

function isExecutable(file) {
  try {
    accessSync(file, fsConstants.X_OK);
    return true;
  } catch {
    return false;
  }
}

async function runRequiredStep(name, command, commandArgs, options = {}) {
  const step = await runCommand(name, command, commandArgs, options);
  if (step.exitCode !== 0) {
    throw new StepError(name, `command failed with exit ${step.exitCode}`, step);
  }
  return step;
}

async function runCommand(name, command, commandArgs, options = {}) {
  const startedAt = new Date().toISOString();
  const stdoutChunks = [];
  const stderrChunks = [];
  const stdoutLog = path.join(result.logsDir, `${slugify(name)}.stdout.log`);
  const stderrLog = path.join(result.logsDir, `${slugify(name)}.stderr.log`);
  const timeoutMs = options.timeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS;

  const recordedArgs = redactArgs(commandArgs);
  console.log(`[pilot] ${name}: ${command} ${recordedArgs.join(" ")}`);

  // Keep stdout/stderr on disk even for successful commands; the result JSON
  // only stores paths so large OpenClaw logs do not bloat the evidence file.
  const step = await new Promise((resolve) => {
    const child = spawn(command, commandArgs, {
      cwd: options.cwd ?? PLUGIN_ROOT,
      env: options.env ?? process.env,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let timedOut = false;
    const stdoutStream = createWriteStream(stdoutLog);
    const stderrStream = createWriteStream(stderrLog);
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGTERM");
      setTimeout(() => {
        if (child.exitCode === null) child.kill("SIGKILL");
      }, 5_000).unref();
    }, timeoutMs);
    timer.unref();

    if (options.stdin !== undefined) {
      child.stdin.end(options.stdin);
    } else {
      child.stdin.end();
    }
    child.stdout.on("data", (chunk) => {
      stdoutChunks.push(chunk);
      stdoutStream.write(chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderrChunks.push(chunk);
      stderrStream.write(chunk);
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      stdoutStream.end();
      stderrStream.end();
      resolve({
        name,
        command,
        args: recordedArgs,
        exitCode: 127,
        signal: undefined,
        timedOut,
        startedAt,
        finishedAt: new Date().toISOString(),
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: String(error),
        stdoutLog,
        stderrLog,
      });
    });
    child.on("close", (exitCode, signal) => {
      clearTimeout(timer);
      stdoutStream.end();
      stderrStream.end();
      resolve({
        name,
        command,
        args: recordedArgs,
        exitCode: timedOut ? 124 : (exitCode ?? 1),
        signal: signal ?? undefined,
        timedOut,
        startedAt,
        finishedAt: new Date().toISOString(),
        stdout: Buffer.concat(stdoutChunks).toString("utf8"),
        stderr: Buffer.concat(stderrChunks).toString("utf8"),
        stdoutLog,
        stderrLog,
      });
    });
  });

  result.steps.push({
    name,
    command,
    args: recordedArgs,
    exitCode: step.exitCode,
    signal: step.signal,
    timedOut: step.timedOut,
    startedAt: step.startedAt,
    finishedAt: step.finishedAt,
    stdoutLog,
    stderrLog,
  });
  return step;
}

function startProcess(name, command, commandArgs, options = {}) {
  const stdoutLog = path.join(result.logsDir, `${slugify(name)}.stdout.log`);
  const stderrLog = path.join(result.logsDir, `${slugify(name)}.stderr.log`);
  const recordedArgs = redactArgs(commandArgs);
  console.log(`[pilot] start ${name}: ${command} ${recordedArgs.join(" ")}`);
  const child = spawn(command, commandArgs, {
    cwd: options.cwd ?? PLUGIN_ROOT,
    env: options.env ?? process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const stdoutStream = createWriteStream(stdoutLog);
  const stderrStream = createWriteStream(stderrLog);
  child.stdout.pipe(stdoutStream);
  child.stderr.pipe(stderrStream);
  const proc = {
    name,
    child,
    stdoutLog,
    stderrLog,
    startedAt: new Date().toISOString(),
  };
  startedProcesses.push(proc);
  result.steps.push({
    name,
    command,
    args: recordedArgs,
    process: true,
    startedAt: proc.startedAt,
    stdoutLog,
    stderrLog,
  });
  child.once("exit", (code, signal) => {
    proc.exitCode = code;
    proc.signal = signal;
    proc.finishedAt = new Date().toISOString();
  });
  child.once("error", (error) => {
    proc.error = String(error);
    proc.finishedAt = new Date().toISOString();
  });
  return proc;
}

async function startOpenClawGateway({ env, gatewayPort, gatewayToken, gatewayTimeoutMs, reason }) {
  const processName = reason === "initial" ? "openclaw-gateway" : `openclaw-gateway-${reason}`;
  const processRef = startProcess(
    processName,
    "openclaw",
    [
      "gateway",
      "run",
      "--dev",
      "--allow-unconfigured",
      "--auth",
      "token",
      "--token",
      gatewayToken,
      "--bind",
      "loopback",
      "--port",
      String(gatewayPort),
      "--ws-log",
      "compact",
    ],
    { cwd: PLUGIN_ROOT, env },
  );
  const health = await waitForGatewayHealth(`ws://127.0.0.1:${gatewayPort}`, {
    env,
    processRef,
    token: gatewayToken,
    timeoutMs: gatewayTimeoutMs,
  });
  return { process: processRef, health };
}

async function stopStartedProcess(proc) {
  if (!proc || proc.child.exitCode !== null) return;
  proc.child.kill("SIGTERM");
  try {
    await withTimeout(waitForExit(proc.child), 5_000, `stop ${proc.name}`);
  } catch {
    proc.child.kill("SIGKILL");
    await waitForExit(proc.child).catch(() => {});
  }
}

async function waitForDaemonHealth(socketPath, { processRef, timeoutMs }) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    assertProcessStillRunning(processRef);
    try {
      const response = await callDaemonHealth(socketPath);
      if (response?.ok === true) {
        return response;
      }
      lastError = new Error(`daemon.health returned ${JSON.stringify(response)}`);
    } catch (error) {
      lastError = error;
    }
    await sleep(250);
  }
  throw new Error(`agent-sec-daemon did not become healthy: ${formatError(lastError)}`);
}

function callDaemonHealth(socketPath) {
  return new Promise((resolve, reject) => {
    const client = net.createConnection(socketPath);
    let data = "";
    const timer = setTimeout(() => {
      client.destroy();
      reject(new Error("daemon.health timed out"));
    }, 2_000);
    client.on("connect", () => {
      client.write(
        `${JSON.stringify({
          id: "pilot-daemon-health",
          method: "daemon.health",
          caller: "pilot-latest-openclaw-e2e",
        })}\n`,
      );
    });
    client.on("data", (chunk) => {
      data += chunk.toString("utf8");
      if (data.includes("\n")) {
        clearTimeout(timer);
        client.end();
        try {
          resolve(JSON.parse(data.trim().split(/\n/u)[0]));
        } catch (error) {
          reject(error);
        }
      }
    });
    client.on("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
  });
}

async function waitForGatewayHealth(gatewayUrl, { env, processRef, token, timeoutMs }) {
  const deadline = Date.now() + timeoutMs;
  let lastError;
  while (Date.now() < deadline) {
    assertProcessStillRunning(processRef);
    const step = await runCommand(
      "openclaw-gateway-health",
      "openclaw",
      [
        "gateway",
        "health",
        "--url",
        gatewayUrl,
        "--json",
        "--timeout",
        "1500",
        "--token",
        token,
      ],
      { cwd: PLUGIN_ROOT, env, timeoutMs: 5_000 },
    );
    if (step.exitCode === 0) {
      try {
        return parseJsonFromOutput(step.stdout);
      } catch (error) {
        lastError = error;
      }
    } else {
      lastError = new StepError("openclaw-gateway-health", "gateway health failed", step);
    }
    await sleep(1_000);
  }
  throw new Error(`OpenClaw gateway did not become healthy: ${formatError(lastError)}`);
}

function assertProcessStillRunning(processRef) {
  if (!processRef) return;
  if (processRef.child.exitCode !== null) {
    throw new Error(
      `${processRef.name} exited early with code=${processRef.exitCode} signal=${processRef.signal}; stdout=${processRef.stdoutLog} stderr=${processRef.stderrLog}`,
    );
  }
}

async function callGatewayRpc(stepName, method, params, { env, gatewayToken, gatewayUrl, timeoutMs }) {
  const startedAt = new Date().toISOString();
  const stdoutLog = path.join(result.logsDir, `${slugify(stepName)}.stdout.log`);
  const stderrLog = path.join(result.logsDir, `${slugify(stepName)}.stderr.log`);
  const stepTimeoutMs = timeoutMs ?? DEFAULT_COMMAND_TIMEOUT_MS;
  console.log(`[pilot] ${stepName}: gateway-rpc ${method}`);
  try {
    // Gateway RPCs are not shell commands, but recording them as steps keeps the
    // final evidence timeline comparable with deploy/config/build commands.
    const payload = await callGatewayRpcDirect({
      gatewayToken,
      gatewayUrl,
      method,
      params,
      timeoutMs: stepTimeoutMs,
    });
    await fs.writeFile(stdoutLog, `${JSON.stringify(payload, null, 2)}\n`);
    await fs.writeFile(stderrLog, "");
    result.steps.push({
      name: stepName,
      command: "gateway-rpc",
      args: [method],
      exitCode: 0,
      timedOut: false,
      startedAt,
      finishedAt: new Date().toISOString(),
      stdoutLog,
      stderrLog,
    });
    return payload;
  } catch (error) {
    await fs.writeFile(stdoutLog, "");
    await fs.writeFile(stderrLog, `${formatError(error)}\n`);
    const step = {
      name: stepName,
      command: "gateway-rpc",
      args: [method],
      exitCode: 1,
      signal: undefined,
      timedOut: false,
      startedAt,
      finishedAt: new Date().toISOString(),
      stdoutLog,
      stderrLog,
    };
    result.steps.push(step);
    throw new StepError(stepName, "gateway RPC failed", step);
  }
}

function callGatewayRpcDirect({ gatewayToken, gatewayUrl, method, params, timeoutMs }) {
  if (typeof WebSocket !== "function") {
    throw new Error("Node.js WebSocket global is unavailable; Node 22+ is required");
  }

  return new Promise((resolve, reject) => {
    const socket = new WebSocket(gatewayUrl);
    const connectId = `connect-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    const requestId = `rpc-${Date.now()}-${Math.random().toString(16).slice(2)}`;
    let connected = false;
    let settled = false;

    const timer = setTimeout(() => {
      settle(new Error(`gateway RPC ${method} timed out after ${timeoutMs}ms`));
    }, timeoutMs);
    timer.unref();

    const settle = (error, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try {
        socket.close();
      } catch {
        // Ignore close errors after a terminal RPC result.
      }
      if (error) {
        reject(error);
      } else {
        resolve(value);
      }
    };

    socket.addEventListener("open", () => {
      socket.send(
        JSON.stringify({
          type: "req",
          id: connectId,
          method: "connect",
          params: {
            minProtocol: 3,
            maxProtocol: 4,
            client: {
              id: "gateway-client",
              version: "agent-sec-openclaw-pilot",
              platform: process.platform,
              mode: "backend",
            },
            role: "operator",
            scopes: ["operator.admin", "operator.read", "operator.write", "operator.approvals"],
            caps: [],
            commands: [],
            permissions: {},
            auth: { token: gatewayToken },
            locale: "en-US",
            userAgent: "agent-sec-openclaw-pilot/0.7.0",
          },
        }),
      );
    });

    socket.addEventListener("message", (event) => {
      let frame;
      try {
        frame = JSON.parse(String(event.data));
      } catch (error) {
        settle(error);
        return;
      }
      if (frame.type === "event") {
        return;
      }
      if (frame.type !== "res") {
        return;
      }
      if (frame.id === connectId) {
        if (frame.ok !== true) {
          settle(new Error(`gateway connect failed: ${JSON.stringify(frame.error ?? frame)}`));
          return;
        }
        connected = true;
        socket.send(
          JSON.stringify({
            type: "req",
            id: requestId,
            method,
            params,
          }),
        );
        return;
      }
      if (frame.id === requestId) {
        if (frame.ok !== true) {
          settle(new Error(`gateway RPC ${method} failed: ${JSON.stringify(frame.error ?? frame)}`));
          return;
        }
        settle(undefined, frame.payload);
      }
    });

    socket.addEventListener("error", () => {
      settle(new Error(`gateway RPC ${method} WebSocket error`));
    });
    socket.addEventListener("close", (event) => {
      if (!settled && !connected) {
        settle(new Error(`gateway closed before connect (${event.code}): ${event.reason}`));
      } else if (!settled) {
        settle(new Error(`gateway closed during RPC ${method} (${event.code}): ${event.reason}`));
      }
    });
  });
}

function assertRuntimeLoaded(data) {
  const status = data?.plugin?.status;
  if (status !== "loaded") {
    throw new Error(`runtime inspect status is ${JSON.stringify(status)}, expected "loaded"`);
  }
}

function summarizeRuntimeInspect(data) {
  const hooks = new Set();
  const text = JSON.stringify(data);
  for (const hookName of [
    "before_dispatch",
    "before_tool_call",
    "after_tool_call",
    "llm_input",
    "llm_output",
    "model_call_started",
    "model_call_ended",
    "agent_end",
  ]) {
    if (text.includes(hookName)) {
      hooks.add(hookName);
    }
  }
  return {
    plugin: data.plugin,
    hookNamesFound: [...hooks].sort(),
    diagnostics: data.diagnostics,
  };
}

function parseNpmPackArtifact(stdout, artifactsDir) {
  try {
    const parsed = JSON.parse(stdout);
    const first = Array.isArray(parsed) ? parsed[0] : parsed;
    if (first?.filename) {
      return path.join(artifactsDir, first.filename);
    }
  } catch {
    // Fall through to a conservative filename search.
  }
  const match = stdout.match(/agent-sec-openclaw-plugin-[^\s]+\.tgz/u);
  return match ? path.join(artifactsDir, match[0]) : undefined;
}

async function stopAllProcesses() {
  for (const proc of [...startedProcesses].reverse()) {
    if (proc.child.exitCode !== null) continue;
    proc.child.kill("SIGTERM");
    try {
      await withTimeout(waitForExit(proc.child), 5_000, `stop ${proc.name}`);
    } catch {
      proc.child.kill("SIGKILL");
      await waitForExit(proc.child).catch(() => {});
    }
  }
  for (const serverRef of [...startedServers].reverse()) {
    await closeServer(serverRef).catch(() => {});
  }
}

function waitForExit(child) {
  return new Promise((resolve, reject) => {
    if (child.exitCode !== null) {
      resolve();
      return;
    }
    child.once("exit", resolve);
    child.once("error", reject);
  });
}

function closeServer(serverRef) {
  return new Promise((resolve, reject) => {
    serverRef.server.close((error) => {
      if (error) {
        reject(error);
        return;
      }
      resolve();
    });
  });
}

async function writeResultFile() {
  if (!result.workdir) return;
  const resultFile = path.join(result.workdir, "pilot-result.json");
  result.resultFile = resultFile;
  await fs.mkdir(result.workdir, { recursive: true });
  await fs.writeFile(resultFile, `${JSON.stringify(result, null, 2)}\n`);
  console.log(`[pilot] result: ${resultFile}`);
}
