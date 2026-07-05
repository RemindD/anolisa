import { spawn } from "node:child_process";
import { createWriteStream } from "node:fs";
import fs from "node:fs/promises";
import net from "node:net";
import path from "node:path";

import {
  parseJsonFromOutput,
  redactArgs,
  sleep,
  slugify,
  withTimeout,
} from "./common.mjs";
import { StepError, formatError } from "./errors.mjs";

// The harness owns stateful mechanics shared by pilot-style e2e tests: command
// logs, child processes, Gateway RPC calls, and the final evidence file.
export function createPilotHarness({
  defaultCommandTimeoutMs,
  pluginRoot,
  result,
  startedProcesses,
  startedServers,
}) {
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
    const timeoutMs = options.timeoutMs ?? defaultCommandTimeoutMs;

    const recordedArgs = redactArgs(commandArgs);
    console.log(`[pilot] ${name}: ${command} ${recordedArgs.join(" ")}`);

    // Keep stdout/stderr on disk even for successful commands; the result JSON
    // only stores paths so large OpenClaw logs do not bloat the evidence file.
    const step = await new Promise((resolve) => {
      const child = spawn(command, commandArgs, {
        cwd: options.cwd ?? pluginRoot,
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
      cwd: options.cwd ?? pluginRoot,
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
      { cwd: pluginRoot, env },
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
    if (!proc || hasChildExited(proc.child)) return;
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
        { cwd: pluginRoot, env, timeoutMs: 5_000 },
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
    if (hasChildExited(processRef.child)) {
      throw new Error(
        `${processRef.name} exited early with code=${processRef.exitCode} signal=${processRef.signal}; stdout=${processRef.stdoutLog} stderr=${processRef.stderrLog}`,
      );
    }
  }

  async function callGatewayRpc(stepName, method, params, { gatewayToken, gatewayUrl, timeoutMs }) {
    const startedAt = new Date().toISOString();
    const stdoutLog = path.join(result.logsDir, `${slugify(stepName)}.stdout.log`);
    const stderrLog = path.join(result.logsDir, `${slugify(stepName)}.stderr.log`);
    const stepTimeoutMs = timeoutMs ?? defaultCommandTimeoutMs;
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

  async function stopAllProcesses() {
    for (const proc of [...startedProcesses].reverse()) {
      if (hasChildExited(proc.child)) continue;
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

  async function writeResultFile() {
    if (!result.workdir) return;
    const resultFile = path.join(result.workdir, "pilot-result.json");
    result.resultFile = resultFile;
    await fs.mkdir(result.workdir, { recursive: true });
    await fs.writeFile(resultFile, `${JSON.stringify(result, null, 2)}\n`);
    console.log(`[pilot] result: ${resultFile}`);
  }

  return {
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
  };
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

function waitForExit(child) {
  return new Promise((resolve, reject) => {
    if (hasChildExited(child)) {
      resolve();
      return;
    }
    child.once("exit", resolve);
    child.once("error", reject);
  });
}

function hasChildExited(child) {
  // Signal-terminated children keep exitCode null, and stale references may
  // reach cleanup after their exit event has already fired.
  return child.exitCode !== null || child.signalCode !== null;
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
