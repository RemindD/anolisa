import type { SecurityCapability } from "../types.js";
import { callAgentSecCli } from "../utils.js";

export const promptAnalyzer: SecurityCapability = {
  id: "prompt-analyzer",
  name: "Prompt Injection Analyzer",
  hooks: ["before_agent_reply"],
  register(api) {
    api.on("before_agent_reply", async (event, ctx) => {
      // TODO: wire to actual agent-sec-cli subcommand once available
      const result = await callAgentSecCli(
        ["analyze", "--text", String(event.cleanedBody ?? "")],
        { timeout: 5000 },
      );

      // FAIL-OPEN: Only block on explicit security decision, not on CLI errors.
      // CLI failures should NOT block agent replies.
      if (result.exitCode === 0 && result.stdout.toLowerCase().includes("injection")) {
        return {
          handled: true,
          reply: { text: `Blocked: ${result.stdout || "Injection attack detected"}` },
          reason: "injection",
        };
      }
      return undefined; // allow (fail-open)
      // No try/catch needed — before_agent_reply is fail-open
    }, { priority: 150 });
  },
};
