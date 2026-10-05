// In-sandbox entry, run by the trusted host as
//   sbx exec -it <sandbox> /opt/study-room/bin/study-room-entry
// It prepares the disposable Pi configuration directory, prints the entry
// banner, and starts or attaches the tmux session that runs Pi as the
// teacher with /workspace mapped to the vault's Study Room/ directory.

import { spawnSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { catalogModel, describe as describeThinking, report, type ThinkingReport } from "../lib/thinking.ts";
import { layout, loadProfile, mainPiArgs, piModel, type Layout, type Profile } from "../lib/profile.ts";
import { MAIN_ROLE, SESSION, listPanes } from "../lib/panes.ts";

const MD_LOG_REMINDER =
  "md-log: link a NEW, EMPTY note; while logging is active keep it view-only in every Obsidian client; /md-unlog before editing it.";

export interface PreparedEntry {
  args: string[];
  env: Record<string, string>;
  banner: string[];
  mainThinking: string;
}

/** Write the disposable Pi agent directory from trusted, root-owned inputs. */
export function prepareAgentDir(p: Profile, l: Layout): void {
  rmSync(join(l.agentDir, "agents"), { recursive: true, force: true });
  rmSync(join(l.agentDir, "extensions"), { recursive: true, force: true });
  for (const dir of [l.agentDir, join(l.agentDir, "agents"), join(l.agentDir, "extensions", "web-search"), join(l.agentDir, "extensions", "web-fetch"), l.sessionDir, l.ephemeral]) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
  }
  const settings = {
    // Never load trust-gated project resources from the vault, in the main
    // session or in researcher children (which pi-interactive-subagents
    // launches without --no-approve).
    defaultProjectTrust: "never",
    enableInstallTelemetry: false,
    enableAnalytics: false,
    quietStartup: "header",
    collapseChangelog: true,
    sessionDir: l.sessionDir,
  };
  writeFileSync(join(l.agentDir, "settings.json"), JSON.stringify(settings, null, 2) + "\n", { mode: 0o600 });
  if (existsSync(l.trustedResearcher)) {
    copyFileSync(l.trustedResearcher, join(l.agentDir, "agents", "researcher.md"));
  }
  // pi-interactive-subagents maps these tool names to fixed paths under the
  // agent directory; one-line shims re-export the pinned implementations.
  writeFileSync(
    join(l.agentDir, "extensions", "web-search", "index.ts"),
    `export { default } from ${JSON.stringify(join(l.runtime, "node_modules", "pi-web-search", "src", "index.ts"))};\n`,
  );
  writeFileSync(
    join(l.agentDir, "extensions", "web-fetch", "index.ts"),
    `export { default } from ${JSON.stringify(join(l.root, "extensions", "web-fetch", "index.ts"))};\n`,
  );
  const searchFile = join(l.agentDir, "web-search.json");
  if (p.search.pi_provider && p.search.model) {
    writeFileSync(searchFile, JSON.stringify({ provider: p.search.pi_provider, model: p.search.model }, null, 2) + "\n");
  } else {
    rmSync(searchFile, { force: true });
  }
}

export async function prepare(p: Profile, l: Layout): Promise<PreparedEntry> {
  const mainModel = p.main.model ? await catalogModel(l.runtime, p.main.pi_provider, p.main.model) : null;
  const researcherModel = p.researcher.model ? await catalogModel(l.runtime, p.researcher.pi_provider, p.researcher.model) : null;
  const mainReport: ThinkingReport = report(mainModel, piModel(p.main) ?? "unset", p.main.thinking);
  const researcherReport: ThinkingReport = report(researcherModel, piModel(p.researcher) ?? "unset", p.researcher.thinking);

  let mainThinking = p.main.thinking;
  const warnings = [...p.warnings];
  if (mainReport.effective !== null && mainReport.clamped) {
    // A main default that cannot honour its requested level needs an explicit,
    // configured fallback (SPEC 14.2); otherwise entry stops.
    if (!p.main.thinking_fallback) {
      throw new Error(
        `${mainReport.model} does not support thinking "${p.main.thinking}" (supported: ${mainReport.supported?.join(", ")}). ` +
          "Choose another main model, or set profiles.main.thinking_fallback on the host to accept a documented fallback.",
      );
    }
    mainThinking = p.main.thinking_fallback;
    warnings.push(`main model cannot use ${p.main.thinking}; using the configured fallback ${mainThinking}`);
  }
  if (mainReport.effective === null && p.main.model) warnings.push(`main model ${mainReport.model} is not in Pi's pinned catalog; effective thinking unknown`);
  if (researcherReport.clamped) warnings.push(`researcher thinking ${describeThinking(researcherReport)}`);

  const providers = Object.entries(p.providers)
    .filter(([, v]) => v.enabled)
    .map(([k, v]) => `${k}${v.experimental ? " (EXPERIMENTAL)" : ""}${v.verified ? "" : " (connectivity not verified)"}`);

  const banner = [
    "── Study Room ──────────────────────────────────────────────",
    ...p.host_summary,
    `Network mode: ${p.network_mode}${p.network_mode === "web" ? " (sandbox-wide public HTTP(S): any agent or shell command can send study notes to any public site)" : ""}`,
    `Providers: ${providers.join(", ") || "none enabled"}`,
    `Main:       ${mainReport.model} · thinking ${describeThinking(mainReport)}${mainThinking !== p.main.thinking ? ` → using ${mainThinking}` : ""}`,
    `Researcher: ${researcherReport.model} · thinking ${describeThinking(researcherReport)}`,
    `Search:     ${piModel(p.search) ?? "uses the researcher's model"}`,
    "Researcher tools: web_search, hardened web_fetch, safe_bash (a command blacklist, not a security boundary).",
    ...warnings.map((w) => `WARNING: ${w}`),
    MD_LOG_REMINDER,
    "────────────────────────────────────────────────────────────",
  ];

  const env: Record<string, string> = {
    PATH: `${join(l.root, "bin")}:${join(l.root, "node", "bin")}:${process.env.PATH ?? "/usr/bin:/bin"}`,
    PI_CODING_AGENT_DIR: l.agentDir,
    PI_SUBAGENT_ALLOWED: "researcher",
    PI_SKIP_VERSION_CHECK: "1",
    PI_TELEMETRY: "0",
    PI_OFFLINE: "1",
    STUDY_ROOM_WORKSPACE: p.workspace,
    STUDY_ROOM_EPHEMERAL: l.ephemeral,
  };
  return { args: mainPiArgs(p, l, mainThinking), env, banner, mainThinking };
}

function liveMainPane(): boolean {
  return listPanes(SESSION).some((pane) => pane.role === MAIN_ROLE && !pane.dead);
}

async function main(): Promise<number> {
  const p = loadProfile();
  const l = layout();
  if (!existsSync(p.workspace)) {
    console.error(`study-room: the Study Room directory is not mounted at ${p.workspace}`);
    return 23;
  }
  prepareAgentDir(p, l);
  let prepared: PreparedEntry;
  try {
    prepared = await prepare(p, l);
  } catch (err: any) {
    console.error(`study-room: ${err?.message ?? err}`);
    return 25;
  }
  for (const line of prepared.banner) console.log(line);
  const env = { ...process.env, ...prepared.env };
  const hasSession = spawnSync("tmux", ["has-session", "-t", SESSION], { stdio: "ignore" }).status === 0;
  if (hasSession && liveMainPane()) {
    return spawnSync("tmux", ["attach-session", "-t", SESSION], { stdio: "inherit", env }).status ?? 1;
  }
  if (hasSession) {
    // Only orphaned researcher panes are left: close them and start over.
    spawnSync("tmux", ["kill-session", "-t", SESSION], { stdio: "ignore" });
  }
  const r = spawnSync(
    "tmux",
    ["new-session", "-s", SESSION, "-c", "/workspace", "--", "pi", ...prepared.args],
    { stdio: "inherit", env },
  );
  return r.status ?? 1;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  main().then(
    (code) => process.exit(code),
    (err) => {
      console.error(`study-room: ${err?.message ?? err}`);
      process.exit(1);
    },
  );
}

