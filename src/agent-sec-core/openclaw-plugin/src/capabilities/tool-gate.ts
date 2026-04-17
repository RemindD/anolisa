import type { SecurityCapability } from "../types.js";
import { callAgentSecCli } from "../utils.js";

export const toolGate: SecurityCapability = {
  id: "tool-gate",
  name: "Tool Call Gate",
  hooks: ["before_tool_call"],
  register(api) {
    const myCfg = (api.pluginConfig as any)?.capabilities?.["tool-gate"] ?? {};
    const riskThreshold = myCfg.riskThreshold ?? "high";

    api.on("before_tool_call", async (event, ctx) => {
      try {
        // TODO: wire to actual agent-sec-cli subcommand once available
        const result = await callAgentSecCli(
          ["check-tool", "--tool", event.toolName],
          { timeout: 5000 },
        );

        // FAIL-OPEN: Only block on explicit security decision, not on CLI errors.
        // CLI failures should NOT block tool calls (crash ≠ threat).
        const stdout = result.stdout.toLowerCase();
        if (result.exitCode === 0 && (stdout.includes("block") || stdout.includes(riskThreshold))) {
          return { block: true, blockReason: result.stdout || "Blocked by agent-sec" };
        }
        return undefined; // allow (fail-open)
      } catch (err) {
        // ⚠️ before_tool_call is the only FAIL-CLOSED hook in OpenClaw.
        // Uncaught throw → all tool calls blocked.
        api.logger.error(`[tool-gate] error: ${err}`);
        return undefined; // crash ≠ threat → allow
      }
    }, { priority: 100 });
  },
};
