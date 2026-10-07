// The non-secret runtime profile the trusted host hands to the sandbox, and
// the sandbox layout derived from it.
//
// The host writes the profile with `sbx exec -u root` into a root-owned file
// (/opt/study-room/etc/profile.json). It contains model selections, the
// network mode, readiness and drift warnings. It never contains credentials:
// provider credentials reach the sandbox only as proxy placeholders in the
// environment (SPEC 15.1).

import { readFileSync } from "node:fs";
import { join } from "node:path";

export const ROOT = process.env.STUDY_ROOM_ROOT || "/opt/study-room";

export interface ModelProfile {
  provider: string; // study-room provider name: openai | kimi
  pi_provider: string; // Pi provider id: openai | kimi-coding
  model: string | null;
  thinking: string;
}

export interface Profile {
  schema: 1;
  installation_id: string;
  network_mode: "balanced" | "web";
  workspace: string; // host path of Study Room/, mounted at the same path
  main: ModelProfile & { thinking_fallback: string | null };
  researcher: ModelProfile & { allowed_model_overrides: string[] };
  search: { provider: string | null; pi_provider: string | null; model: string | null };
  providers: Record<string, { enabled: boolean; experimental: boolean; verified: boolean }>;
  host_summary: string[];
  warnings: string[];
  lock_fingerprint: string;
}

export class ProfileError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ProfileError";
  }
}

const LEVELS = new Set(["off", "minimal", "low", "medium", "high", "xhigh", "max"]);
const PI_PROVIDERS: Record<string, string> = { openai: "openai", kimi: "kimi-coding" };

export function validateProfile(raw: unknown): Profile {
  const p = raw as Profile;
  const problems: string[] = [];
  if (!p || typeof p !== "object") throw new ProfileError("profile is not an object");
  if (p.schema !== 1) problems.push("schema must be 1");
  if (p.network_mode !== "balanced" && p.network_mode !== "web") problems.push("network_mode must be balanced or web");
  if (typeof p.workspace !== "string" || !p.workspace.startsWith("/")) problems.push("workspace must be an absolute path");
  for (const name of ["main", "researcher"] as const) {
    const m = p[name];
    if (!m || PI_PROVIDERS[m.provider] !== m.pi_provider) problems.push(`${name}.provider/pi_provider mismatch`);
    if (!m || !LEVELS.has(m.thinking)) problems.push(`${name}.thinking invalid`);
    if (m && m.model !== null && (typeof m.model !== "string" || /[/:\s]/.test(m.model))) problems.push(`${name}.model must be a bare model id`);
  }
  if (p.researcher && !Array.isArray(p.researcher.allowed_model_overrides)) problems.push("researcher.allowed_model_overrides must be a list");
  if (!Array.isArray(p.warnings) || !Array.isArray(p.host_summary)) problems.push("warnings and host_summary must be lists");
  if (problems.length) throw new ProfileError(`invalid profile: ${problems.join("; ")}`);
  return p;
}

export function loadProfile(path = join(ROOT, "etc", "profile.json")): Profile {
  let text: string;
  try {
    text = readFileSync(path, "utf8");
  } catch {
    throw new ProfileError(`Study Room is not configured in this sandbox (${path} missing); start it with \`study-room run\` on the host`);
  }
  return validateProfile(JSON.parse(text));
}

export interface Layout {
  root: string;
  runtime: string;
  node: string;
  learn: string;
  subagents: string;
  etc: string;
  trustedResearcher: string;
  home: string;
  agentDir: string;
  sessionDir: string;
  ephemeral: string;
  workspaceLink: string;
}

export function layout(home = process.env.HOME || "/home/agent", root = ROOT): Layout {
  const state = join(home, ".study-room");
  return {
    root,
    runtime: join(root, "runtime"),
    node: join(root, "node", "bin", "node"),
    learn: join(root, "upstream", "learn"),
    subagents: join(root, "upstream", "pi-interactive-subagents"),
    etc: join(root, "etc"),
    trustedResearcher: join(root, "etc", "agents", "researcher.md"),
    home,
    agentDir: join(state, "pi-agent"),
    sessionDir: join(state, "sessions"),
    ephemeral: join(state, "ephemeral"),
    workspaceLink: "/workspace",
  };
}

export function piModel(m: { pi_provider: string | null; model: string | null }): string | null {
  return m.pi_provider && m.model ? `${m.pi_provider}/${m.model}` : null;
}

/** Approved Learn resources (SPEC 10.2), loaded in place from the read-only checkout. */
export function learnResources(l: Layout) {
  return {
    skills: [join(l.learn, "skills", "teach")],
    extensions: [
      join(l.learn, "extensions", "ask-user-question.ts"),
      join(l.learn, "extensions", "quiz.ts"),
      join(l.learn, "extensions", "md-log.ts"),
    ],
  };
}

/** Arguments for the main teaching session. */
export function mainPiArgs(p: Profile, l: Layout, mainThinking: string): string[] {
  const model = piModel(p.main);
  if (!model) throw new ProfileError("no main model is configured; set profiles.main.model on the host (see `study-room models openai`)");
  const res = learnResources(l);
  const args = [
    "--session-dir", l.sessionDir,
    "--no-approve", // never load trust-gated project config from the vault
    "--no-extensions", // nothing discovered: only the explicit list below
    ...res.extensions.flatMap((e) => ["-e", e]),
    "-e", join(l.subagents, "pi-extension", "subagents", "index.ts"),
    "-e", join(l.root, "extensions", "study-room-guard", "index.ts"),
    "--no-skills",
    ...res.skills.flatMap((s) => ["--skill", s]),
    "--no-prompt-templates",
    "--model", model,
    "--thinking", mainThinking,
  ];
  return args;
}
