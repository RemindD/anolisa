import type { SecurityCapability } from "../types.js";
import { callAgentSecCli } from "../utils.js";

export const llmAudit: SecurityCapability = {
  id: "llm-audit",
  name: "LLM Output Auditor",
  hooks: ["llm_output"],
  register(api) {
    api.on("llm_output", async (event, ctx) => {
      // TODO: wire to actual agent-sec-cli subcommand once available
      // Fire-and-forget — does not block the main flow
      await callAgentSecCli(
        ["audit", "--provider", String(event.provider ?? ""), "--model", String(event.model ?? "")],
        { timeout: 3000 },
      );
      // void hook — return value is not consumed
    }, { priority: 0 });
  },
};
