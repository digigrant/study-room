// Hard limits for explicitly approved live connectivity checks (SPEC 20.2).
//
// Loaded only by study-room-live-check. It counts provider requests, caps
// the output tokens of each request, allows at most the configured number of
// web_search calls, and shuts Pi down once the request budget is spent. The
// running count is written to STUDY_ROOM_BUDGET_FILE so the checker can
// report it and fail a run that went over.

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { writeFileSync } from "node:fs";

function limit(name: string, fallback: number): number {
  const n = Number(process.env[name]);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

export default function verificationBudget(pi: ExtensionAPI) {
  const maxRequests = limit("STUDY_ROOM_BUDGET_MAX_REQUESTS", 1);
  const maxOutput = limit("STUDY_ROOM_BUDGET_MAX_OUTPUT", 64);
  const maxSearch = limit("STUDY_ROOM_BUDGET_MAX_SEARCH", 0);
  const file = process.env.STUDY_ROOM_BUDGET_FILE;
  let requests = 0;
  let searches = 0;
  const record = (extra: Record<string, unknown> = {}) => {
    if (file) writeFileSync(file, JSON.stringify({ requests, searches, maxRequests, maxOutput, maxSearch, ...extra }));
  };
  record();

  pi.on("before_provider_request", async (event: any) => {
    requests++;
    if (requests > maxRequests) {
      // Hard stop: this runs before the HTTP call, so exiting here guarantees
      // the over-budget request never leaves the sandbox. (Throwing from a
      // handler is reported by Pi but does not cancel the request.)
      requests--;
      record({ exceeded: true });
      process.exit(75);
    }
    record();
    const p = event?.payload;
    if (p && typeof p === "object") {
      // Responses API, Chat Completions, and Anthropic Messages field names.
      for (const key of ["max_output_tokens", "max_completion_tokens", "max_tokens"]) {
        if (key in p) p[key] = Math.min(Number(p[key]) || maxOutput, maxOutput);
      }
      if (!("max_output_tokens" in p) && !("max_tokens" in p) && !("max_completion_tokens" in p)) {
        p.max_output_tokens = maxOutput;
      }
    }
    return p;
  });

  pi.on("tool_call", async (event: any) => {
    // Once the last allowed model turn has been used, no tool result may
    // trigger another turn: block and terminate the batch.
    if (requests >= maxRequests) {
      return { block: true, terminate: true, reason: `verification budget: the ${maxRequests}-turn limit is reached` };
    }
    if (event.toolName !== "web_search") return undefined;
    searches++;
    record();
    if (searches > maxSearch) {
      return { block: true, reason: `verification budget: at most ${maxSearch} web_search call(s)` };
    }
    return undefined;
  });
}
