#!/usr/bin/env node
import fs from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

import {
  PLUGIN_ID,
  extractVersion,
  findFreePort,
  parseJsonFromOutput,
} from "./pilot/common.mjs";
import { parseArgs, printHelp, resolveOpenClawBin } from "./pilot/args.mjs";
import { formatError, serializeError } from "./pilot/errors.mjs";
import {
  assertGatewayTrafficProbe,
  assertPolicyMatrix,
  runGatewayPolicyMatrix,
  runGatewayTrafficProbe,
} from "./pilot/gateway-probes.mjs";
import { createPilotHarness } from "./pilot/harness.mjs";
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

const {
  assertProcessStillRunning,
  assertRuntimeLoaded,
  callGatewayRpc,
  parseNpmPackArtifact,
  runRequiredStep,
  startOpenClawGateway,
  startProcess,
  stopAllProcesses,
  stopStartedProcess,
  summarizeRuntimeInspect,
  waitForDaemonHealth,
  writeResultFile,
} = createPilotHarness({
  defaultCommandTimeoutMs: DEFAULT_COMMAND_TIMEOUT_MS,
  pluginRoot: PLUGIN_ROOT,
  result,
  startedProcesses,
  startedServers,
});

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
  // The CLI wrapper reads this file to keep policy-triggering inputs
  // deterministic while passing normal agent-sec-cli calls through.
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

  // The mock model is only responsible for deterministic tool-turn behavior;
  // prompts still travel through real OpenClaw Gateway sessions and plugin hooks.
  const mockModel = await startMockModelServer({
    logsDir,
    registerServer: (serverRef) => startedServers.push(serverRef),
  });
  result.paths.mockModelBaseUrl = mockModel.baseUrl;
  result.mockModel = {
    baseUrl: mockModel.baseUrl,
    requestsLog: mockModel.requestsLog,
  };
  // Point OpenClaw at the mock model through normal config so the Gateway uses
  // the same model-selection path as a user-run session.
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
    // Shared starter used for the initial Gateway process and any explicit
    // restart probes that need a fresh runtime.
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

  const inspectHelp = await runRequiredStep(
    "openclaw-plugin-inspect-help",
    "openclaw",
    ["plugins", "inspect", "--help"],
    { cwd: PLUGIN_ROOT, env: baseEnv, timeoutMs: DEFAULT_COMMAND_TIMEOUT_MS },
  );
  const runtimeInspectArgs = inspectHelp.stdout.includes("--runtime")
    ? ["plugins", "inspect", PLUGIN_ID, "--runtime", "--json"]
    : ["plugins", "inspect", PLUGIN_ID, "--json"];
  const runtimeInspect = await runRequiredStep(
    "openclaw-plugin-runtime-inspect",
    "openclaw",
    runtimeInspectArgs,
    { cwd: PLUGIN_ROOT, env: baseEnv, timeoutMs: DEFAULT_COMMAND_TIMEOUT_MS },
  );
  const runtimeInspectJson = parseJsonFromOutput(runtimeInspect.stdout);
  assertRuntimeLoaded(runtimeInspectJson);
  result.runtimeInspect = summarizeRuntimeInspect(runtimeInspectJson);
  result.runtimeInspect.args = runtimeInspectArgs;
  result.runtimeInspect.rawLog = runtimeInspect.stdoutLog;

  if (!args.skipGateway) {
    // Happy-path probe: verify one full model-driven Gateway turn reaches the
    // plugin hooks, agent-sec-cli, tool execution, and observability output.
    result.gatewayTrafficProbe = await runGatewayTrafficProbe({
      assertProcessStillRunning,
      callGatewayRpc,
      dataDir,
      gatewayToken,
      gatewayUrl,
      logsDir,
      mockModel,
      processRef: gatewayProcess,
      runtimeInspect: result.runtimeInspect,
    });
    assertGatewayTrafficProbe(result.gatewayTrafficProbe);
    // Policy matrix: mutate plugin config in-place, let Gateway hot reload
    // settle, then assert behavior from session/model/approval evidence.
    result.policyMatrix = await runGatewayPolicyMatrix({
      callGatewayRpc,
      cliLogPath: agentSecCliCallsLog,
      env: baseEnv,
      gatewayToken,
      gatewayUrl,
      logsDir,
      mockModel,
      pluginRoot: PLUGIN_ROOT,
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

  // Direct hook probe stays as a lower-level diagnostic lane. The Gateway probes
  // are the acceptance signal; this makes hook-level failures easier to isolate.
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
