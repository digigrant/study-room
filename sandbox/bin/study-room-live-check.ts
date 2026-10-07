// Explicit live connectivity checks, run by the host only after consent:
//   sbx exec <sandbox> /opt/study-room/bin/study-room-live-check <check> < spec.json
// The spec (verification model, thinking, limits) comes from the lock via the
// host. The sandbox holds only proxy placeholders; a successful request
// proves Docker Sandboxes substituted the real credential outside the
// sandbox. Output is one JSON line per check; no secret is ever printed.

import { spawn, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { renderResearcherDefinition } from "../lib/policy.ts";
import { ROOT, layout } from "../lib/profile.ts";

export interface LiveSpec {
  pi_provider: string;
  model: string;
  thinking: string;
  limits: { max_requests: number; max_output_tokens: number; timeout_seconds: number };
  research_limits: { max_model_turns: number; max_search_calls: number; max_output_tokens: number; timeout_seconds: number };
  placeholder_env: string; // OPENAI_API_KEY or KIMI_API_KEY
  placeholder_prefix: string; // e.g. "sr-openai-"
  /** Hermetic tests only: a models.json pointing the provider at a local fake. */
  models_json?: string;
}

export interface CheckResult {
  check: string;
  status: "passed" | "failed" | "skipped";
  detail: string;
  requests?: number;
  searches?: number;
}

function piArgsBase(spec: LiveSpec): string[] {
  return ["--print", "--no-session", "--no-approve", "--no-context-files", "--model", `${spec.pi_provider}/${spec.model}`, "--thinking", spec.thinking];
}

interface RunResult {
  status: number | null;
  signal: NodeJS.Signals | null;
  error?: Error;
  stdout: string;
  stderr: string;
}

/** Run Pi with a hard wall-clock limit (killed with SIGKILL when it is reached). */
function run(args: string[], env: Record<string, string>, timeoutS: number): Promise<RunResult> {
  return new Promise((resolve) => {
    const child = spawn(join(ROOT, "bin", "pi"), args, { env: { ...process.env, ...env }, stdio: ["ignore", "pipe", "pipe"] });
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    child.stdout.on("data", (d) => (stdout += d));
    child.stderr.on("data", (d) => (stderr += d));
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill("SIGKILL");
    }, timeoutS * 1000);
    child.on("close", (status, signal) => {
      clearTimeout(timer);
      resolve({ status, signal, stdout, stderr, error: timedOut ? new Error("timeout") : undefined });
    });
    child.on("error", (error) => {
      clearTimeout(timer);
      resolve({ status: null, signal: null, stdout, stderr, error });
    });
  });
}

function budget(file: string): { requests: number; searches: number; exceeded?: boolean } {
  try {
    return JSON.parse(readFileSync(file, "utf8"));
  } catch {
    return { requests: 0, searches: 0 };
  }
}

function tempAgentDir(spec: LiveSpec, withSearch: boolean): string {
  const dir = mkdtempSync(join(tmpdir(), "sr-live-"));
  writeFileSync(join(dir, "settings.json"), JSON.stringify({ defaultProjectTrust: "never", retry: { enabled: false, provider: { maxRetries: 0 } }, enableInstallTelemetry: false }));
  if (spec.models_json) writeFileSync(join(dir, "models.json"), spec.models_json);
  if (withSearch) {
    // Search uses the cheap verification model; it never falls back to the teaching model.
    writeFileSync(join(dir, "web-search.json"), JSON.stringify({ provider: spec.pi_provider, model: spec.model }));
  }
  return dir;
}

export function placeholderCheck(spec: LiveSpec, env = process.env): CheckResult {
  const value = env[spec.placeholder_env] ?? "";
  if (!value) return { check: "placeholder", status: "failed", detail: `${spec.placeholder_env} is not set in the sandbox` };
  if (!value.startsWith(spec.placeholder_prefix)) {
    return { check: "placeholder", status: "failed", detail: `${spec.placeholder_env} does not look like a Study Room placeholder (refusing to use it)` };
  }
  return { check: "placeholder", status: "passed", detail: `${spec.placeholder_env} holds a placeholder (${value.length} chars); the real credential stays on the host` };
}

export async function providerCheck(spec: LiveSpec): Promise<CheckResult> {
  const ph = placeholderCheck(spec);
  if (ph.status !== "passed") return { ...ph, check: "provider" };
  const agentDir = tempAgentDir(spec, false);
  const budgetFile = join(agentDir, "budget.json");
  try {
    const r = await run(
      [...piArgsBase(spec), "--no-extensions", "--no-tools", "-e", join(ROOT, "extensions", "verification-budget", "index.ts"), "Reply with exactly this text and nothing else: STUDY-ROOM-OK"],
      {
        PI_CODING_AGENT_DIR: agentDir,
        PI_OFFLINE: "1",
        PI_SKIP_VERSION_CHECK: "1",
        STUDY_ROOM_BUDGET_FILE: budgetFile,
        STUDY_ROOM_BUDGET_MAX_REQUESTS: String(spec.limits.max_requests),
        STUDY_ROOM_BUDGET_MAX_OUTPUT: String(spec.limits.max_output_tokens),
        STUDY_ROOM_BUDGET_MAX_SEARCH: "0",
      },
      spec.limits.timeout_seconds,
    );
    const b = budget(budgetFile);
    if (r.error || r.signal) return { check: "provider", status: "failed", detail: `timed out after ${spec.limits.timeout_seconds}s`, requests: b.requests };
    if (b.exceeded || r.status === 75 || b.requests > spec.limits.max_requests) return { check: "provider", status: "failed", detail: "stopped at the request budget", requests: b.requests };
    const ok = r.status === 0 && /STUDY-ROOM-OK/.test(r.stdout);
    const err = (r.stderr || r.stdout).trim().split("\n").slice(-1)[0] ?? "";
    return {
      check: "provider",
      status: ok ? "passed" : "failed",
      detail: ok ? `${spec.pi_provider}/${spec.model} answered through the proxy` : `no expected answer (exit ${r.status}): ${err.slice(0, 200)}`,
      requests: b.requests,
    };
  } finally {
    rmSync(agentDir, { recursive: true, force: true });
  }
}

export async function researchCheck(spec: LiveSpec): Promise<CheckResult> {
  const ph = placeholderCheck(spec);
  if (ph.status !== "passed") return { ...ph, check: "research" };
  const l = layout();
  const agentDir = tempAgentDir(spec, true);
  const budgetFile = join(agentDir, "budget.json");
  try {
    mkdirSync(join(agentDir, "ext"), { recursive: true });
    const body = renderResearcherDefinition({ model: `${spec.pi_provider}/${spec.model}`, thinking: spec.thinking }).split("---").slice(2).join("---");
    const sys = join(agentDir, "researcher.md");
    writeFileSync(sys, body);
    const task =
      "Use web_search exactly once to find the official Python documentation page for the built-in function len(). " +
      "Then answer in one short sentence and include the source URL. Do not use any other tool.";
    const r = await run(
      [
        ...piArgsBase(spec),
        "--no-extensions",
        "--tools", "web_search,web_fetch,safe_bash",
        "-e", join(l.runtime, "node_modules", "pi-web-search", "src", "index.ts"),
        "-e", join(ROOT, "extensions", "web-fetch", "index.ts"),
        "-e", join(l.subagents, "pi-extension", "subagents", "tools", "safe-bash.ts"),
        "-e", join(ROOT, "extensions", "verification-budget", "index.ts"),
        "--append-system-prompt", sys,
        task,
      ],
      {
        PI_CODING_AGENT_DIR: agentDir,
        PI_OFFLINE: "1",
        PI_SKIP_VERSION_CHECK: "1",
        STUDY_ROOM_BUDGET_FILE: budgetFile,
        STUDY_ROOM_BUDGET_MAX_REQUESTS: String(spec.research_limits.max_model_turns),
        STUDY_ROOM_BUDGET_MAX_OUTPUT: String(spec.research_limits.max_output_tokens),
        STUDY_ROOM_BUDGET_MAX_SEARCH: String(spec.research_limits.max_search_calls),
      },
      spec.research_limits.timeout_seconds,
    );
    const b = budget(budgetFile);
    if (r.error || r.signal) return { check: "research", status: "failed", detail: `timed out after ${spec.research_limits.timeout_seconds}s`, requests: b.requests, searches: b.searches };
    if (b.exceeded || r.status === 75) return { check: "research", status: "failed", detail: "stopped at the model-turn budget", requests: b.requests, searches: b.searches };
    const cited = /https?:\/\/\S+/.test(r.stdout);
    const ok = r.status === 0 && b.searches === 1 && cited;
    return {
      check: "research",
      status: ok ? "passed" : "failed",
      detail: ok
        ? "researcher loadout searched once and returned a cited answer"
        : `searches=${b.searches}, cited=${cited}, exit ${r.status}: ${(r.stderr || "").trim().split("\n").slice(-1)[0]?.slice(0, 200) ?? ""}`,
      requests: b.requests,
      searches: b.searches,
    };
  } finally {
    rmSync(agentDir, { recursive: true, force: true });
  }
}

export function githubCheck(expectedLogin: string, repo: string): CheckResult {
  // Non-mutating: identity and repository read access only.
  const user = spawnSync("gh", ["api", "user", "--jq", ".login"], { encoding: "utf8", timeout: 30_000 });
  if (user.status !== 0) return { check: "github", status: "failed", detail: `gh api user failed: ${(user.stderr || "").trim().split("\n")[0]}` };
  const login = user.stdout.trim();
  if (login !== expectedLogin) return { check: "github", status: "failed", detail: `authenticated as ${login}, expected ${expectedLogin}` };
  const r = spawnSync("gh", ["api", `repos/${repo}`, "--jq", ".full_name"], { encoding: "utf8", timeout: 30_000 });
  if (r.status !== 0) return { check: "github", status: "failed", detail: `cannot read ${repo}` };
  return { check: "github", status: "passed", detail: `authenticated as ${login}; ${repo} is readable (nothing was changed)` };
}

async function main(): Promise<void> {
  const check = process.argv[2];
  const input = readFileSync(0, "utf8");
  const spec = JSON.parse(input || "{}");
  let result: CheckResult;
  if (check === "placeholder") result = placeholderCheck(spec);
  else if (check === "provider") result = await providerCheck(spec);
  else if (check === "research") result = await researchCheck(spec);
  else if (check === "github") result = githubCheck(spec.expected_login, spec.repo);
  else result = { check: String(check), status: "skipped", detail: "unknown check" };
  console.log(JSON.stringify(result));
  process.exit(result.status === "failed" ? 1 : 0);
}

if (import.meta.url === `file://${process.argv[1]}`) void main();
