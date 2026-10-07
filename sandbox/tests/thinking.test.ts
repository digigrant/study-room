import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { LEVELS, catalogIds, catalogModel, describe as describeThinking, effectiveLevel, piAiDir, report, type ModelMeta } from "../lib/thinking.ts";

const kimiLike: ModelMeta = {
  id: "k",
  provider: "kimi-coding",
  reasoning: true,
  thinkingLevelMap: { off: null, minimal: null, low: "low", medium: null, high: "high", xhigh: null, max: "max" },
};
const openaiLike: ModelMeta = {
  id: "o",
  provider: "openai",
  reasoning: true,
  thinkingLevelMap: { off: "none", minimal: null, low: "low", medium: "medium", high: "high", xhigh: "xhigh", max: null },
};

describe("effective thinking", () => {
  it("maps a Kimi-style medium request upward to high, visibly", () => {
    const r = report(kimiLike, "kimi-coding/k", "medium");
    assert.equal(r.effective, "high");
    assert.equal(r.direction, "up");
    assert.match(describeThinking(r), /requested medium, effective high \(Pi maps medium UP to high/);
  });
  it("clamps max down where max is unsupported", () => {
    assert.equal(effectiveLevel(openaiLike, "max"), "xhigh");
    assert.equal(report(openaiLike, "openai/o", "max").clamped, true);
  });
  it("keeps supported levels and reports unknown models honestly", () => {
    assert.equal(effectiveLevel(openaiLike, "medium"), "medium");
    assert.equal(effectiveLevel({ id: "n", provider: "x", reasoning: false }, "high"), "off");
    assert.match(describeThinking(report(null, "openai/unknown", "max")), /effective unknown/);
  });
});

const runtime = join(process.env.STUDY_ROOM_ROOT || "/opt/study-room", "runtime");
const haveRuntime = existsSync(join(piAiDir(runtime), "dist", "models.js"));

describe("against Pi's pinned catalog", { skip: haveRuntime ? false : "the pinned Pi runtime is not installed here" }, () => {
  it("matches pi-ai's clampThinkingLevel for every OpenAI and Kimi model and level", async () => {
    const piModels = await import(pathToFileURL(join(piAiDir(runtime), "dist", "models.js")).href);
    let compared = 0;
    for (const provider of ["openai", "kimi-coding"]) {
      for (const id of await catalogIds(runtime, provider)) {
        const model = (await catalogModel(runtime, provider, id))!;
        for (const level of LEVELS) {
          assert.equal(effectiveLevel(model, level), piModels.clampThinkingLevel(model, level), `${provider}/${id} ${level}`);
          compared++;
        }
      }
    }
    assert.ok(compared > 50, `compared ${compared} cases`);
  });
  it("shows the documented Kimi medium→high mapping in the pinned catalog", async () => {
    const ids = await catalogIds(runtime, "kimi-coding");
    assert.ok(ids.length > 0);
    const m = (await catalogModel(runtime, "kimi-coding", ids[0]))!;
    assert.equal(effectiveLevel(m, "medium"), "high");
  });
});
