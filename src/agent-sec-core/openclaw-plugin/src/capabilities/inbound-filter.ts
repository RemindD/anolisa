import type { SecurityCapability } from "../types.js";
import { callAgentSecCli } from "../utils.js";

export const inboundFilter: SecurityCapability = {
  id: "inbound-filter",
  name: "Inbound Message Filter",
  hooks: ["before_dispatch"],
  register(api) {
    api.on("before_dispatch", async (event, ctx) => {
      // TODO: wire to actual agent-sec-cli subcommand once available
      const result = await callAgentSecCli(
        ["scan", "--content", String(event.content ?? event.body ?? "")],
        { timeout: 3000 },
      );

      // FAIL-OPEN: Only block on explicit security decision, not on CLI errors.
      // CLI failures (missing subcommand, timeout, etc.) should NOT block messages.
      if (result.exitCode === 0 && result.stdout.toLowerCase().includes("block")) {
        return { handled: true, text: `Message blocked by security policy: ${result.stdout}` };
      }
      return undefined; // allow (fail-open)
    }, { priority: 200 });
  },
};
