// The live-check machinery against a local fake provider: proves the hard
// limits (request count, output cap, one search) without any real request.

import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { FakeProvider, modelsJson, type LoggedRequest, type Reply } from "./helpers/fake-provider.ts";
import { placeholderCheck, providerCheck, researchCheck, type LiveSpec } from "../bin/study-room-live-check.ts";

const ROOT = process.env.STUDY_ROOM_ROOT || "/opt/study-room";
const skip = existsSync(join(ROOT, "runtime", "node_modules", "@earendil-works", "pi-coding-agent", "package.json"))
  ? false
  : "the pinned runtime is not installed here (run inside the sandbox image)";

let mode: "ok" | "loop" | "search-twice" = "ok";

function verifier(req: LoggedRequest): Reply {
  if (mode === "ok") return { text: "STUDY-ROOM-OK" };
  if (mode === "loop") return { tool: { name: "safe_bash", args: { command: "true" } } };
  // search-twice: call web_search on every turn; the budget blocks the second.
  if (req.last.role === "tool" && /verification budget/.test(req.last.text)) return { text: "Done. Source: https://docs.python.org/3/library/functions.html#len" };
  return { tool: { name: "web_search", args: { query: "python len builtin" } } };
}

describe("live checks under hard limits", { skip, timeout: 120_000 }, () => {
  const provider = new FakeProvider({ "fake-verify": verifier });
  let spec: LiveSpec;
  const env = { ...process.env };

  before(async () => {
    const port = await provider.start();
    spec = {
      pi_provider: "openai",
      model: "fake-verify",
      thinking: "low",
      limits: { max_requests: 1, max_output_tokens: 64, timeout_seconds: 60 },
      research_limits: { max_model_turns: 3, max_search_calls: 1, max_output_tokens: 400, timeout_seconds: 90 },
      placeholder_env: "OPENAI_API_KEY",
      placeholder_prefix: "sr-openai-",
      models_json: modelsJson(port, ["fake-verify"]),
    };
    process.env.OPENAI_API_KEY = "sr-openai-PLACEHOLDER-test";
    for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]) delete process.env[k];
  });
  after(async () => {
    process.env = env;
    await provider.stop();
  });

  it("refuses to run without a Study Room placeholder", () => {
    assert.equal(placeholderCheck(spec, { OPENAI_API_KEY: "sk-real-looking-value" }).status, "failed");
    assert.equal(placeholderCheck(spec, {}).status, "failed");
    assert.equal(placeholderCheck(spec, { OPENAI_API_KEY: "sr-openai-abc" }).status, "passed");
  });

  it("makes exactly one capped request for the provider check", async () => {
    mode = "ok";
    const before = provider.log.length;
    const r = await providerCheck(spec);
    assert.equal(r.status, "passed", r.detail);
    assert.equal(r.requests, 1);
    const sent = provider.log.slice(before);
    assert.equal(sent.length, 1);
    assert.equal(sent[0].auth, "Bearer sr-openai-PLACEHOLDER-test");
    assert.deepEqual(sent[0].tools, [], "no tools in the basic check");
    assert.ok(sent[0].maxTokens !== null && sent[0].maxTokens <= spec.limits.max_output_tokens, `output cap reached the request (${sent[0].maxTokens})`);
  });

  it("stops a run that tries to exceed its request budget", async () => {
    mode = "loop";
    const before = provider.log.length;
    const r = await researchCheck(spec);
    assert.equal(r.status, "failed");
    assert.ok(provider.log.length - before <= spec.research_limits.max_model_turns, `sent ${provider.log.length - before} requests`);
  });

  it("allows only one web_search call", async () => {
    mode = "search-twice";
    const r = await researchCheck(spec);
    assert.ok((r.searches ?? 0) >= 1);
    const blocked = provider.log.some((q) => q.last.role === "tool" && /at most 1 web_search/.test(q.last.text));
    assert.ok(blocked, "the second search was blocked by the budget");
  });
});
