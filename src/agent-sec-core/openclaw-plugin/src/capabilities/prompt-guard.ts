import type { SecurityCapability } from "../types.js";
import { callAgentSecCli } from "../utils.js";

const DEFAULT_POLICY = "## Security Policy\n- Follow least privilege principle.";

export const promptGuard: SecurityCapability = {
  id: "prompt-guard",
  name: "Prompt Security Guard",
  hooks: ["before_prompt_build"],
  register(api) {
    api.on("before_prompt_build", async (event, ctx) => {
      // TODO: wire to actual agent-sec-cli subcommand once available
      const result = await callAgentSecCli(
        ["get-policy"],
        { timeout: 3000 },
      );

      // Prototype: use stdout as policy text, fallback to default
      const policy = result.stdout || DEFAULT_POLICY;
      return { appendSystemContext: policy };
      // No try/catch needed — before_prompt_build is fail-open
    }, { priority: 50 });
  },
};
