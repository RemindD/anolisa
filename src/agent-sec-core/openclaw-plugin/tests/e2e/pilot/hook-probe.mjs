import fs from "node:fs/promises";
import path from "node:path";
import { pathToFileURL } from "node:url";

import { normalizeJsonValue, sleep, withTimeout, writeExecutable } from "./common.mjs";
import { serializeError } from "./errors.mjs";

const DEFAULT_HOOK_TIMEOUT_MS = 35_000;

export async function runHookProbe({ env, logsDir, pluginRoot, repoRoot, workdir, skipFailureProbes }) {
  // Hook probe is supplemental coverage. It exercises direct plugin API handlers
  // and fail-open behavior that are hard to force through one Gateway chat turn.
  const probe = {
    mode: "openclaw-plugin-api-hook-probe",
    note:
      "This probe executes handlers registered by the plugin's OpenClaw plugin API entry. It is not a substitute for a model-driven gateway chat turn.",
    registeredHooks: [],
    logs: [],
    cases: [],
  };
  const capture = await capturePluginHooks({
    pluginConfig: {
      promptScanBlock: true,
      piiScanUserInput: true,
      codeScanRequireApproval: true,
      capabilities: {
        "pii-scan-user-input": { enableBlock: true },
        "skill-ledger": { policy: "warn" },
      },
    },
    pluginRoot,
  });
  probe.registeredHooks = capture.hooks.map((hook) => ({
    hookName: hook.hookName,
    priority: hook.priority,
  }));
  probe.logs.push(...capture.logs);

  const skillDir = path.join(workdir, "fixtures", "skills", "pilot-skill");
  await fs.mkdir(skillDir, { recursive: true });
  await fs.writeFile(
    path.join(skillDir, "SKILL.md"),
    "# Pilot Skill\n\nThis fixture is used by the OpenClaw pilot e2e hook probe.\n",
  );

  const normalCases = [
    // These cases cover every registered capability at least once. They are not
    // policy acceptance by themselves; Gateway matrix cases above own that.
    {
      name: "prompt-scan-before-dispatch",
      hookName: "before_dispatch",
      event: {
        content: "hello from the OpenClaw latest pilot",
        body: "hello from the OpenClaw latest pilot",
        senderId: "pilot-user",
        sessionKey: "pilot-session",
        isGroup: false,
      },
      ctx: beforeDispatchCtx(),
    },
    {
      name: "pii-scan-before-dispatch",
      hookName: "before_dispatch",
      event: {
        content: "Contact me at alice@example.com for the pilot.",
        body: "Contact me at alice@example.com for the pilot.",
        senderId: "pilot-user",
        sessionKey: "pilot-session",
        isGroup: false,
      },
      ctx: beforeDispatchCtx(),
    },
    {
      name: "scan-code-before-tool-call",
      hookName: "before_tool_call",
      event: {
        toolName: "exec",
        params: { command: "openclaw plugins disable agent-sec" },
        runId: "pilot-run",
        sessionId: "pilot-session",
        toolCallId: "pilot-tool-code",
      },
      ctx: toolCtx(repoRoot, "pilot-tool-code", "exec"),
    },
    {
      name: "skill-ledger-before-tool-call",
      hookName: "before_tool_call",
      event: {
        toolName: "read",
        params: { file_path: path.join(skillDir, "SKILL.md") },
        runId: "pilot-run",
        sessionId: "pilot-session",
        toolCallId: "pilot-tool-skill",
      },
      ctx: toolCtx(repoRoot, "pilot-tool-skill", "read"),
    },
    {
      name: "observability-llm-input",
      hookName: "llm_input",
      event: {
        runId: "pilot-run",
        sessionId: "pilot-session",
        provider: "pilot-provider",
        model: "pilot-model",
        systemPrompt: "system",
        prompt: "hello",
        historyMessages: [{ role: "user", content: "hello" }],
        imagesCount: 0,
      },
      ctx: agentCtx(repoRoot),
    },
    {
      name: "observability-model-call-started",
      hookName: "model_call_started",
      event: {
        runId: "pilot-run",
        callId: "pilot-call",
        sessionKey: "pilot-session",
        sessionId: "pilot-session",
        provider: "pilot-provider",
        model: "pilot-model",
        api: "responses",
        transport: "http",
      },
      ctx: agentCtx(repoRoot),
    },
    {
      name: "observability-model-call-ended",
      hookName: "model_call_ended",
      event: {
        runId: "pilot-run",
        callId: "pilot-call",
        sessionKey: "pilot-session",
        sessionId: "pilot-session",
        provider: "pilot-provider",
        model: "pilot-model",
        api: "responses",
        transport: "http",
        durationMs: 25,
        outcome: "completed",
      },
      ctx: agentCtx(repoRoot),
    },
    {
      name: "pii-and-observability-llm-output",
      hookName: "llm_output",
      event: {
        runId: "pilot-run",
        sessionId: "pilot-session",
        provider: "pilot-provider",
        model: "pilot-model",
        resolvedRef: "pilot-provider/pilot-model",
        assistantTexts: ["The pilot finished."],
        lastAssistant: "The pilot finished.",
        usage: { input: 8, output: 4, total: 12 },
      },
      ctx: agentCtx(repoRoot),
    },
    {
      name: "observability-after-tool-call",
      hookName: "after_tool_call",
      event: {
        toolName: "exec",
        params: { command: "echo ok" },
        runId: "pilot-run",
        sessionId: "pilot-session",
        toolCallId: "pilot-tool-after",
        result: { content: "ok" },
        durationMs: 10,
      },
      ctx: toolCtx(repoRoot, "pilot-tool-after", "exec"),
    },
    {
      name: "observability-agent-end",
      hookName: "agent_end",
      event: {
        runId: "pilot-run",
        success: true,
        durationMs: 50,
        messages: [
          { role: "user", content: [{ type: "text", text: "hello" }] },
          { role: "assistant", content: [{ type: "text", text: "done" }] },
        ],
      },
      ctx: agentCtx(repoRoot),
    },
  ];

  for (const testCase of normalCases) {
    probe.cases.push(await invokeCapturedHookCase(capture, testCase));
  }

  if (!skipFailureProbes) {
    // Negative probes must fail open: missing, broken, invalid, or slow CLI
    // behavior should be recorded without throwing from plugin hooks.
    const missingCliEnv = {
      ...env,
      PATH: await makeEmptyBinDir(workdir, "missing-cli-bin"),
    };
    probe.cases.push(
      await invokeCapturedHookCase(capture, {
        name: "failure-missing-agent-sec-cli",
        hookName: "before_dispatch",
        event: {
          content: "hello while agent-sec-cli is absent",
          body: "hello while agent-sec-cli is absent",
          senderId: "pilot-user",
          sessionKey: "pilot-session",
        },
        ctx: beforeDispatchCtx(),
        env: missingCliEnv,
      }),
    );

    probe.cases.push(
      await invokeCapturedHookCase(capture, {
        name: "failure-agent-sec-cli-nonzero",
        hookName: "before_dispatch",
        event: {
          content: "hello with nonzero CLI",
          body: "hello with nonzero CLI",
          senderId: "pilot-user",
          sessionKey: "pilot-session",
        },
        ctx: beforeDispatchCtx(),
        env: await makeFakeCliEnv(env, workdir, "nonzero", `#!/usr/bin/env bash
echo "pilot nonzero" >&2
exit 42
`),
      }),
    );

    probe.cases.push(
      await invokeCapturedHookCase(capture, {
        name: "failure-agent-sec-cli-invalid-json",
        hookName: "before_dispatch",
        event: {
          content: "hello with invalid JSON",
          body: "hello with invalid JSON",
          senderId: "pilot-user",
          sessionKey: "pilot-session",
        },
        ctx: beforeDispatchCtx(),
        env: await makeFakeCliEnv(env, workdir, "invalid-json", `#!/usr/bin/env bash
printf '{not-json'
`),
      }),
    );

    probe.cases.push(
      await invokeCapturedHookCase(capture, {
        name: "failure-agent-sec-cli-timeout",
        hookName: "before_dispatch",
        event: {
          content: "hello with timeout CLI",
          body: "hello with timeout CLI",
          senderId: "pilot-user",
          sessionKey: "pilot-session",
        },
        ctx: beforeDispatchCtx(),
        env: await makeFakeCliEnv(env, workdir, "timeout", `#!/usr/bin/env bash
sleep 20
`),
      }),
    );
  }

  await sleep(1_000);
  const probeFile = path.join(logsDir, "hook-probe.json");
  await fs.writeFile(probeFile, `${JSON.stringify(probe, null, 2)}\n`);
  probe.resultFile = probeFile;
  return probe;
}

export function assertHookProbe(probe) {
  const requiredHookNames = [
    "before_dispatch",
    "before_tool_call",
    "after_tool_call",
    "llm_input",
    "llm_output",
    "model_call_started",
    "model_call_ended",
    "agent_end",
  ];
  for (const hookName of requiredHookNames) {
    if (!probe.registeredHooks.some((hook) => hook.hookName === hookName)) {
      throw new Error(`hook probe did not register required hook ${hookName}`);
    }
  }
  for (const testCase of probe.cases) {
    if (testCase.matchedHandlers <= 0) {
      throw new Error(`hook probe case ${testCase.name} matched no handlers`);
    }
    const unexpectedError = testCase.results.find((item) => item.error);
    if (unexpectedError) {
      throw new Error(
        `hook probe case ${testCase.name} failed: ${JSON.stringify(unexpectedError.error)}`,
      );
    }
  }
}

async function capturePluginHooks({ pluginConfig, pluginRoot }) {
  // Import dist with a cache-busting query so repeated pilot runs in the same
  // Node process cannot reuse stale plugin registration state.
  const distEntry = path.join(pluginRoot, "dist", "index.js");
  const moduleUrl = `${pathToFileURL(distEntry).href}?pilot=${Date.now()}`;
  const entry = (await import(moduleUrl)).default;
  if (!entry || typeof entry.register !== "function") {
    throw new Error(`plugin entry does not expose register(api): ${distEntry}`);
  }

  const hooks = [];
  const logs = [];
  const api = {
    pluginConfig,
    logger: {
      info: (message) => logs.push(`[INFO] ${message}`),
      warn: (message) => logs.push(`[WARN] ${message}`),
      error: (message) => logs.push(`[ERROR] ${message}`),
      debug: (message) => logs.push(`[DEBUG] ${message}`),
    },
    on: (hookName, handler, opts) => {
      hooks.push({
        hookName,
        handler,
        priority: opts?.priority ?? 0,
      });
    },
  };
  entry.register(api);
  hooks.sort((left, right) => right.priority - left.priority);
  return { hooks, logs };
}

async function invokeCapturedHookCase(capture, testCase) {
  // Some failure probes need a temporary PATH. Restore process.env after each
  // case because plugin code reads env at hook invocation time.
  const previousEnv = process.env;
  if (testCase.env) {
    process.env = { ...testCase.env };
  }
  const startedAt = Date.now();
  const matchingHooks = capture.hooks.filter((hook) => hook.hookName === testCase.hookName);
  const results = [];
  try {
    for (const hook of matchingHooks) {
      const hookStartedAt = Date.now();
      try {
        const value = await withTimeout(
          Promise.resolve(hook.handler(testCase.event, testCase.ctx)),
          DEFAULT_HOOK_TIMEOUT_MS,
          `${testCase.name}:${testCase.hookName}`,
        );
        results.push({
          hookName: hook.hookName,
          priority: hook.priority,
          durationMs: Date.now() - hookStartedAt,
          result: normalizeJsonValue(value),
        });
      } catch (error) {
        results.push({
          hookName: hook.hookName,
          priority: hook.priority,
          durationMs: Date.now() - hookStartedAt,
          error: serializeError(error),
        });
      }
    }
  } finally {
    if (testCase.env) {
      process.env = previousEnv;
    }
  }
  return {
    name: testCase.name,
    hookName: testCase.hookName,
    matchedHandlers: matchingHooks.length,
    durationMs: Date.now() - startedAt,
    results,
  };
}

function beforeDispatchCtx() {
  return {
    channelId: "qa-channel",
    accountId: "pilot-account",
    conversationId: "pilot-conversation",
    sessionKey: "pilot-session",
    senderId: "pilot-user",
  };
}

function agentCtx(repoRoot) {
  return {
    channelId: "qa-channel",
    channel: "qa-channel",
    sessionKey: "pilot-session",
    sessionId: "pilot-session",
    runId: "pilot-run",
    agentId: "pilot-agent",
    workspaceDir: repoRoot,
  };
}

function toolCtx(repoRoot, toolCallId, toolName) {
  return {
    ...agentCtx(repoRoot),
    toolName,
    toolCallId,
  };
}

async function makeEmptyBinDir(workdir, name) {
  const dir = path.join(workdir, "fake-bin", name);
  await fs.mkdir(dir, { recursive: true });
  return dir;
}

async function makeFakeCliEnv(env, workdir, name, script) {
  const dir = await makeEmptyBinDir(workdir, name);
  await writeExecutable(path.join(dir, "agent-sec-cli"), script);
  return {
    ...env,
    PATH: `${dir}${path.delimiter}${env.PATH ?? ""}`,
  };
}
