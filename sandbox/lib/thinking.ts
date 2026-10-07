// Requested versus effective thinking levels (SPEC 11.2, 14.2).
//
// Pi clamps a requested level to what the selected model supports. Study
// Room shows both the requested and the effective level, so a Kimi model
// mapping "medium" upward to "high" is never silent. The algorithm mirrors
// pi-ai's clampThinkingLevel; tests compare the two over the pinned catalog.

import { existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

export const LEVELS = ["off", "minimal", "low", "medium", "high", "xhigh", "max"] as const;
export type Level = (typeof LEVELS)[number];

export interface ModelMeta {
  id: string;
  provider: string;
  reasoning?: boolean;
  thinkingLevelMap?: Partial<Record<Level, string | null>>;
}

export function supportedLevels(model: ModelMeta): Level[] {
  if (!model.reasoning) return ["off"];
  return LEVELS.filter((level) => {
    const mapped = model.thinkingLevelMap?.[level];
    if (mapped === null) return false;
    if (level === "xhigh" || level === "max") return mapped !== undefined;
    return true;
  });
}

export function effectiveLevel(model: ModelMeta, requested: string): Level {
  const available = supportedLevels(model);
  if ((available as string[]).includes(requested)) return requested as Level;
  const idx = (LEVELS as readonly string[]).indexOf(requested);
  if (idx === -1) return available[0] ?? "off";
  for (let i = idx; i < LEVELS.length; i++) if (available.includes(LEVELS[i])) return LEVELS[i];
  for (let i = idx - 1; i >= 0; i--) if (available.includes(LEVELS[i])) return LEVELS[i];
  return available[0] ?? "off";
}

export interface ThinkingReport {
  model: string;
  requested: string;
  effective: Level | null; // null when the model is not in the pinned catalog
  supported: Level[] | null;
  clamped: boolean;
  direction: "up" | "down" | null;
}

export function report(model: ModelMeta | null, label: string, requested: string): ThinkingReport {
  if (!model) return { model: label, requested, effective: null, supported: null, clamped: false, direction: null };
  const effective = effectiveLevel(model, requested);
  const clamped = effective !== requested;
  let direction: "up" | "down" | null = null;
  if (clamped) {
    direction = (LEVELS as readonly string[]).indexOf(effective) > (LEVELS as readonly string[]).indexOf(requested) ? "up" : "down";
  }
  return { model: label, requested, effective, supported: supportedLevels(model), clamped, direction };
}

export function describe(r: ThinkingReport): string {
  if (r.effective === null) return `requested ${r.requested}, effective unknown (model not in the pinned catalog)`;
  if (!r.clamped) return `requested ${r.requested}, effective ${r.effective}`;
  return `requested ${r.requested}, effective ${r.effective} (Pi maps ${r.requested} ${r.direction === "up" ? "UP" : "down"} to ${r.effective} for this model)`;
}

// ── Pinned catalog lookup ───────────────────────────────────────────────────

const CATALOG_MODULES: Record<string, [string, string]> = {
  openai: ["openai.models.js", "OPENAI_MODELS"],
  "kimi-coding": ["kimi-coding.models.js", "KIMI_CODING_MODELS"],
};

export function piAiDir(runtime: string): string {
  // pi-coding-agent ships pi-ai inside its own node_modules (npm-shrinkwrap).
  const nested = join(runtime, "node_modules", "@earendil-works", "pi-coding-agent", "node_modules", "@earendil-works", "pi-ai");
  if (existsSync(nested)) return nested;
  return join(runtime, "node_modules", "@earendil-works", "pi-ai");
}

export async function catalogModel(runtime: string, piProvider: string, id: string): Promise<ModelMeta | null> {
  const entry = CATALOG_MODULES[piProvider];
  if (!entry) return null;
  const file = join(piAiDir(runtime), "dist", "providers", entry[0]);
  if (!existsSync(file)) return null;
  const mod = await import(pathToFileURL(file).href);
  const models = mod[entry[1]];
  const list: ModelMeta[] = Array.isArray(models) ? models : Object.values(models ?? {});
  return list.find((m) => m.id === id) ?? null;
}

export async function catalogIds(runtime: string, piProvider: string): Promise<string[]> {
  const entry = CATALOG_MODULES[piProvider];
  if (!entry) return [];
  const file = join(piAiDir(runtime), "dist", "providers", entry[0]);
  if (!existsSync(file)) return [];
  const mod = await import(pathToFileURL(file).href);
  const models = mod[entry[1]];
  const list: ModelMeta[] = Array.isArray(models) ? models : Object.values(models ?? {});
  return list.map((m) => m.id);
}
