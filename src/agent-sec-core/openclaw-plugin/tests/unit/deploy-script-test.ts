import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import {
  chmodSync,
  existsSync,
  mkdirSync,
  mkdtempSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { afterEach, describe, it } from "node:test";

const DEPLOY_SCRIPT = resolve("scripts/deploy.sh");

type DeployOptions = {
  inspectStdoutPrefixLogs?: boolean;
  inspectHasRuntime?: boolean;
  installHelpMode?: "blocking" | "deprecated-noop" | "no-force" | "no-unsafe";
  runtimeStatus?: string;
  version?: string;
};

type DeployResult = {
  log: string;
  stderr: string;
  stdout: string;
  status: number | null;
};

function hostSupportsConversationAccess(version: string): boolean {
  // OpenClaw added plugins.entries.*.hooks.allowConversationAccess validation in
  // 2026.4.24. The fake CLI rejects the key before that version to prove
  // deploy.sh gates the config before execution instead of relying on fallback.
  const match = version.match(/([0-9]{4})\.([0-9]+)\.([0-9]+)/);
  if (match === null) {
    return false;
  }

  const current = match.slice(1).map((part) => Number(part));
  const minimum = [2026, 4, 24];
  for (let index = 0; index < minimum.length; index += 1) {
    if (current[index] !== minimum[index]) {
      return current[index] > minimum[index];
    }
  }
  return true;
}

const tempDirs: string[] = [];

afterEach(() => {
  for (const dir of tempDirs.splice(0)) {
    rmSync(dir, { recursive: true, force: true });
  }
});

function createExecutable(path: string, content: string): void {
  writeFileSync(path, content, "utf8");
  chmodSync(path, 0o755);
}

function createFakeJq(binDir: string): void {
  createExecutable(
    join(binDir, "jq"),
    `#!/usr/bin/env node
const { readFileSync } = require("node:fs");
const args = process.argv.slice(2);
const raw = args[0] === "-r";
const query = raw ? args[1] : args[0];
const file = raw ? args[2] : args[1];
const input = file ? readFileSync(file, "utf8") : readFileSync(0, "utf8");
const json = JSON.parse(input);

if (query === ".version") {
  console.log(json.version ?? "null");
} else if (query === ".plugin.status // \\"unknown\\"") {
  console.log(json.plugin?.status ?? "unknown");
} else if (query === ".diagnostics[]?.message") {
  for (const diagnostic of json.diagnostics ?? []) {
    if (diagnostic?.message) {
      console.log(diagnostic.message);
    }
  }
} else {
  process.exit(2);
}
`,
  );
}

function createFakeOpenClaw(binDir: string): void {
  // This fake models the parts of the OpenClaw CLI contract deploy.sh depends on:
  // installer help text, inspect shape, runtime status, and config validation.
  createExecutable(
    join(binDir, "openclaw"),
    `#!/usr/bin/env bash
set -euo pipefail

printf '%s\\n' "$*" >> "\${OPENCLAW_FAKE_LOG:?}"

if [[ "\${1:-}" == "--version" ]]; then
    echo "OpenClaw \${OPENCLAW_FAKE_VERSION:-2026.4.14} (test)"
    exit 0
fi

if [[ "\${1:-}" == "plugins" && "\${2:-}" == "install" && "\${3:-}" == "--help" ]]; then
    # The exact help wording is intentional: deploy.sh keys off installer
    # semantics, not only version or flag presence.
    if [[ "\${OPENCLAW_FAKE_INSTALL_HELP:-blocking}" == "no-force" ]]; then
        echo "Usage: openclaw plugins install <package>"
    elif [[ "\${OPENCLAW_FAKE_INSTALL_HELP:-blocking}" == "deprecated-noop" ]]; then
        echo "Usage: openclaw plugins install <package> --force --dangerously-force-unsafe-install"
        echo "  --dangerously-force-unsafe-install  Deprecated no-op; security.installPolicy may still block"
    elif [[ "\${OPENCLAW_FAKE_INSTALL_HELP:-blocking}" == "no-unsafe" ]]; then
        echo "Usage: openclaw plugins install <package> --force"
    else
        echo "Usage: openclaw plugins install <package> --force --dangerously-force-unsafe-install"
        echo "  --dangerously-force-unsafe-install  Bypass built-in dangerous-code install"
        echo "                                      blocking (plugin hooks may still block)"
    fi
    exit 0
fi

if [[ "\${1:-}" == "plugins" && "\${2:-}" == "install" ]]; then
    echo "installed"
    exit 0
fi

if [[ "$*" == "config set plugins.entries.agent-sec.hooks.allowConversationAccess true" ]]; then
    if [[ "\${OPENCLAW_FAKE_ALLOW_CONVERSATION_ACCESS:-1}" != "1" ]]; then
        echo "unknown config key: plugins.entries.agent-sec.hooks.allowConversationAccess" >&2
        exit 2
    fi
    echo "configured"
    exit 0
fi

if [[ "$*" == "plugins inspect --help" ]]; then
    if [[ "\${OPENCLAW_FAKE_INSPECT_RUNTIME:-0}" == "1" ]]; then
        echo "Usage: openclaw plugins inspect <id> --json --runtime"
    else
        echo "Usage: openclaw plugins inspect <id> --json"
    fi
    exit 0
fi

if [[ "$*" == "plugins inspect agent-sec --json" ]]; then
    status="\${OPENCLAW_FAKE_RUNTIME_STATUS:-loaded}"
    if [[ "\${OPENCLAW_FAKE_INSPECT_STDOUT_PREFIX_LOGS:-0}" == "1" ]]; then
        echo "[plugins] [agent-sec] registered: scan-code -> [before_tool_call]"
        echo "[plugins] [agent-sec] 5/5 capabilities active"
    fi
    printf '{"plugin":{"id":"agent-sec","status":"%s"},"diagnostics":[{"message":"runtime status %s"}]}\\n' "$status" "$status"
    exit 0
fi

if [[ "$*" == "plugins inspect agent-sec --runtime --json" ]]; then
    status="\${OPENCLAW_FAKE_RUNTIME_STATUS:-loaded}"
    if [[ "\${OPENCLAW_FAKE_INSPECT_STDOUT_PREFIX_LOGS:-0}" == "1" ]]; then
        echo "[plugins] [agent-sec] registered: scan-code -> [before_tool_call]"
        echo "[plugins] [agent-sec] 5/5 capabilities active"
    fi
    printf '{"plugin":{"id":"agent-sec","status":"%s"},"diagnostics":[{"message":"runtime status %s"}]}\\n' "$status" "$status"
    exit 0
fi

echo "unexpected fake openclaw args: $*" >&2
exit 2
`,
  );
}

function createPluginFixture(rootDir: string): string {
  const pluginDir = join(rootDir, "plugin");
  mkdirSync(join(pluginDir, "dist"), { recursive: true });
  writeFileSync(join(pluginDir, "openclaw.plugin.json"), '{"version":"0.7.0"}\n', "utf8");
  writeFileSync(join(pluginDir, "dist", "index.js"), "export {};\n", "utf8");
  return pluginDir;
}

function runDeploy(options: DeployOptions = {}): DeployResult {
  const rootDir = mkdtempSync(join(tmpdir(), "agent-sec-openclaw-deploy-"));
  tempDirs.push(rootDir);
  const binDir = join(rootDir, "bin");
  const logPath = join(rootDir, "openclaw.log");
  mkdirSync(binDir, { recursive: true });
  createFakeOpenClaw(binDir);
  createFakeJq(binDir);
  createExecutable(join(binDir, "agent-sec-cli"), "#!/usr/bin/env bash\nexit 0\n");

  const pluginDir = createPluginFixture(rootDir);
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    // Keep the fake host's schema behavior coupled to the requested version so
    // tests catch accidental unconditional allowConversationAccess writes.
    OPENCLAW_FAKE_ALLOW_CONVERSATION_ACCESS: hostSupportsConversationAccess(
      options.version ?? "2026.4.14",
    )
      ? "1"
      : "0",
    OPENCLAW_FAKE_LOG: logPath,
    OPENCLAW_FAKE_INSPECT_RUNTIME: options.inspectHasRuntime === true ? "1" : "0",
    OPENCLAW_FAKE_INSPECT_STDOUT_PREFIX_LOGS:
      options.inspectStdoutPrefixLogs === true ? "1" : "0",
    OPENCLAW_FAKE_RUNTIME_STATUS: options.runtimeStatus ?? "loaded",
    OPENCLAW_FAKE_VERSION: options.version ?? "2026.4.14",
    PATH: `${binDir}:${process.env.PATH ?? ""}`,
  };
  env.OPENCLAW_FAKE_INSTALL_HELP = options.installHelpMode ?? "blocking";
  delete env.OPENCLAW_COMPATIBILITY_HOST_VERSION;
  delete env.OPENCLAW_HOME;
  delete env.OPENCLAW_STATE_DIR;
  delete env.OPENCLAW_VERSION;

  const result = spawnSync("bash", [DEPLOY_SCRIPT, pluginDir], {
    cwd: resolve("."),
    encoding: "utf8",
    env,
  });

  return {
    log: existsSync(logPath) ? readFileSync(logPath, "utf8") : "",
    stderr: result.stderr,
    stdout: result.stdout,
    status: result.status,
  };
}

describe("deploy.sh", () => {
  it("uses the unsafe flag on the legacy blocking baseline and verifies loading via inspect --json", () => {
    const result = runDeploy({ version: "2026.4.14" });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /OpenClaw: 2026\.4\.14/);
    assert.match(result.stdout, /仍启用内置危险代码阻断/);
    assert.match(result.stdout, /plugins inspect agent-sec --json/);
    assert.match(result.log, /plugins install --help/);
    assert.match(result.log, /plugins inspect --help/);
    assert.match(result.log, /plugins install .* --force --dangerously-force-unsafe-install/);
    assert.match(result.log, /plugins inspect agent-sec --json/);
    assert.doesNotMatch(result.log, /plugins inspect agent-sec --runtime --json/);
    assert.doesNotMatch(
      result.log,
      /config set plugins\.entries\.agent-sec\.hooks\.allowConversationAccess true/,
    );
  });

  it("parses inspect JSON when legacy hosts print plugin logs to stdout first", () => {
    const result = runDeploy({ inspectStdoutPrefixLogs: true, version: "2026.4.14" });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /OpenClaw: 2026\.4\.14/);
    assert.match(result.stdout, /plugins inspect agent-sec --json/);
    assert.match(result.log, /plugins inspect agent-sec --json/);
    assert.doesNotMatch(result.stderr, /parse error/);
    assert.doesNotMatch(result.stderr, /输出不是可解析 JSON/);
  });

  it("uses the unsafe flag and runtime inspect on blocking hosts that expose --runtime", () => {
    const result = runDeploy({ inspectHasRuntime: true, version: "2026.5.28" });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /OpenClaw: 2026\.5\.28/);
    assert.match(result.stdout, /plugins inspect agent-sec --runtime --json/);
    assert.match(result.log, /plugins inspect --help/);
    assert.match(
      result.log,
      /config set plugins\.entries\.agent-sec\.hooks\.allowConversationAccess true/,
    );
    assert.match(result.log, /plugins inspect agent-sec --json/);
    assert.match(result.log, /plugins inspect agent-sec --runtime --json/);
    assert.match(result.log, /plugins install .* --force --dangerously-force-unsafe-install/);
  });

  it("does not use the unsafe flag when OpenClaw marks it as a deprecated no-op", () => {
    const result = runDeploy({
      installHelpMode: "deprecated-noop",
      inspectHasRuntime: true,
      version: "2026.6.10",
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /OpenClaw: 2026\.6\.10/);
    assert.match(result.stdout, /不需要 legacy --dangerously-force-unsafe-install/);
    assert.match(result.log, /plugins install .* --force/);
    assert.doesNotMatch(result.log, /plugins install .* --force --dangerously-force-unsafe-install/);
  });

  it("skips conversation access config before OpenClaw 2026.4.24", () => {
    const result = runDeploy({ version: "2026.4.23" });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /OpenClaw: 2026\.4\.23/);
    assert.match(result.stdout, /跳过 plugins\.entries\.agent-sec\.hooks\.allowConversationAccess=true/);
    assert.match(result.stdout, /OpenClaw 2026\.4\.24 引入/);
    assert.doesNotMatch(
      result.log,
      /config set plugins\.entries\.agent-sec\.hooks\.allowConversationAccess true/,
    );
  });

  it("configures conversation access starting with OpenClaw 2026.4.24", () => {
    const result = runDeploy({ version: "2026.4.24" });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /OpenClaw: 2026\.4\.24/);
    assert.match(result.stdout, /允许 agent-sec 检查大模型输入输出安全/);
    assert.match(
      result.log,
      /config set plugins\.entries\.agent-sec\.hooks\.allowConversationAccess true/,
    );
  });

  it("uses the unsafe flag for source-checkout builds that still advertise blocking semantics", () => {
    const result = runDeploy({
      inspectHasRuntime: true,
      version: "2026.6.10",
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /OpenClaw: 2026\.6\.10/);
    assert.match(result.stdout, /仍启用内置危险代码阻断/);
    assert.match(result.log, /plugins install .* --force --dangerously-force-unsafe-install/);
  });

  it("does not use the unsafe flag when the install CLI does not expose it", () => {
    const result = runDeploy({
      installHelpMode: "no-unsafe",
      version: "2026.6.11",
    });

    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /OpenClaw: 2026\.6\.11/);
    assert.match(result.stdout, /不需要 legacy --dangerously-force-unsafe-install/);
    assert.doesNotMatch(result.log, /dangerously-force-unsafe-install/);
  });

  it("fails before install when OpenClaw is below the supported floor", () => {
    const result = runDeploy({ version: "2026.4.13" });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /OpenClaw >=2026\.4\.14/);
    assert.doesNotMatch(result.log, /plugins install .* --force/);
  });

  it("fails before install when OpenClaw install help does not expose --force", () => {
    const result = runDeploy({ installHelpMode: "no-force" });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /不支持 --force/);
    assert.match(result.log, /plugins install --help/);
    assert.doesNotMatch(result.log, /plugins install .* --force/);
  });

  it("fails when runtime inspection does not report a loaded plugin", () => {
    const result = runDeploy({ inspectHasRuntime: true, runtimeStatus: "error" });

    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /plugins inspect agent-sec --runtime --json 状态为 error/);
    assert.match(result.stderr, /runtime status error/);
    assert.match(result.log, /plugins install .* --force/);
    assert.match(result.log, /plugins inspect agent-sec --runtime --json/);
  });
});
