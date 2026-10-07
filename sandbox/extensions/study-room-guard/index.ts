// Study Room guard: policy and lifecycle glue for the main teaching session.
//
// Loaded only into the main Pi session (never into the researcher child).
// It enforces the researcher policy in front of the unmodified
// pi-interactive-subagents extension, cleans up orphaned researcher panes,
// and keeps the active network mode, model/thinking levels, and the md-log
// editing rule visible.

import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import { existsSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { checkLoadout, checkSpawn, findLoadout, findSessionFile, type ResearcherPolicy } from "../../lib/policy.ts";
import { layout, loadProfile, piModel, type Profile } from "../../lib/profile.ts";
import { killSubagentPanes, markMainPane, subagentPanes } from "../../lib/panes.ts";
import { PANE_CLOSED_GRACE_MS, PaneClosureWatch } from "../../lib/closure.ts";

export const MD_LOG_REMINDER =
  "md-log: link a NEW, EMPTY note, keep it view-only in every Obsidian client while logging is active, and run /md-unlog before editing it.";

function loadPolicy(profile: Profile): ResearcherPolicy {
  const l = layout();
  const model = piModel(profile.researcher);
  if (!model) throw new Error("researcher model is not configured");
  return {
    model,
    thinking: profile.researcher.thinking,
    allowedModelOverrides: profile.researcher.allowed_model_overrides,
    trustedDefinition: readFileSync(l.trustedResearcher, "utf8"),
    agentDir: process.env.PI_CODING_AGENT_DIR || l.agentDir,
  };
}

export default function studyRoomGuard(pi: ExtensionAPI) {
  let profile: Profile | null = null;
  let policy: ResearcherPolicy | null = null;
  let loadError: string | null = null;
  try {
    profile = loadProfile();
    policy = loadPolicy(profile);
  } catch (err: any) {
    loadError = err?.message ?? String(err);
  }

  // pi-interactive-subagents waits for a researcher by reading its tmux pane.
  // If the pane is closed before the researcher prints its exit sentinel, the
  // package would wait forever; this watch reports the closure through the
  // package's own `.exit` sidecar instead (SPEC 11.4: tmux pane closure).
  const closure = new PaneClosureWatch({
    panes: () => subagentPanes(),
    writeExit: (sessionFile: string, message: string) => {
      const exitFile = `${sessionFile}.exit`;
      if (!existsSync(exitFile)) writeFileSync(exitFile, JSON.stringify({ type: "error", errorMessage: message }));
    },
  });
  let closureTimer: ReturnType<typeof setInterval> | null = null;

  pi.on("tool_result", async (event: any) => {
    if (event.toolName !== "subagent" && event.toolName !== "subagent_message") return undefined;
    const d = event.details;
    if (d?.status === "started" && typeof d.sessionFile === "string") closure.started(d.sessionFile, String(d.name ?? ""));
    return undefined;
  });

  pi.on("message_end", async (event: any) => {
    const m = event?.message;
    if (m?.customType === "subagent_result" && typeof m.details?.sessionFile === "string") closure.finished(m.details.sessionFile);
    return undefined;
  });

  pi.on("tool_call", async (event: any, ctx: any) => {
    if (event.toolName !== "subagent" && event.toolName !== "subagent_message") return undefined;
    if (!policy) {
      return { block: true, reason: `Study Room policy unavailable, subagents disabled: ${loadError}` };
    }
    if (event.toolName === "subagent") {
      const decision = checkSpawn(event.input ?? {}, policy, ctx.cwd ?? process.cwd());
      return decision.allow ? undefined : { block: true, reason: decision.reason };
    }
    // subagent_message: a running researcher is only steered; a finished one is
    // resumed from its saved loadout, which must still be the trusted one.
    const name = typeof event.input?.name === "string" ? event.input.name : "";
    const loadout = findLoadout(ctx.sessionManager.getSessionDir(), ctx.sessionManager.getSessionId(), name);
    if (!loadout) return undefined; // unknown names are refused by the package itself
    const decision = checkLoadout(loadout, policy);
    if (!decision.allow) return { block: true, reason: decision.reason };
    // A sidecar left from an earlier closure would end the resumed run at once.
    const entry = findSessionFile(ctx.sessionManager.getSessionDir(), ctx.sessionManager.getSessionId(), name);
    if (entry && !closure.isTracked(entry)) rmSync(`${entry}.exit`, { force: true });
    return undefined;
  });

  pi.on("session_start", async (_event: any, ctx: any) => {
    markMainPane(process.env.TMUX_PANE);
    if (!closureTimer) {
      closureTimer = setInterval(() => closure.tick(Date.now()), Math.min(2000, PANE_CLOSED_GRACE_MS));
      closureTimer.unref?.();
    }
    // Any researcher pane alive now belongs to a previous parent: an orphan.
    const orphans = killSubagentPanes();
    if (ctx.hasUI) {
      if (orphans.length) ctx.ui.notify(`Closed ${orphans.length} orphaned researcher pane(s) from an earlier session.`, "info");
      if (loadError) ctx.ui.notify(`Study Room: ${loadError}`, "error");
      if (profile) {
        ctx.ui.setStatus(
          "study-room",
          `net:${profile.network_mode} · researcher ${piModel(profile.researcher) ?? "unset"} (${profile.researcher.thinking})`,
        );
      }
      ctx.ui.notify(MD_LOG_REMINDER, "info");
    }
  });

  pi.on("session_shutdown", async (event: any) => {
    if (closureTimer) clearInterval(closureTimer);
    closureTimer = null;
    closure.clear();
    // Parent exit: researchers cannot deliver results any more; stop them.
    if (event?.reason === "quit") killSubagentPanes();
  });

  pi.registerCommand("study-room", {
    description: "Show Study Room status: network mode, models, thinking levels, researchers",
    handler: async (_args: string, ctx: any) => {
      if (!profile) {
        ctx.ui.notify(`Study Room profile unavailable: ${loadError}`, "error");
        return;
      }
      const running = subagentPanes().map((p) => `${p.agent} in ${p.id}`);
      const lines = [
        `network mode: ${profile.network_mode}`,
        `main: ${piModel(profile.main) ?? "unset"} (requested ${profile.main.thinking})`,
        `researcher: ${piModel(profile.researcher) ?? "unset"} (requested ${profile.researcher.thinking})`,
        `search: ${piModel(profile.search) ?? "follows the researcher model"}`,
        `researchers running: ${running.length ? running.join(", ") : "none"}`,
        ...profile.warnings.map((w) => `warning: ${w}`),
        MD_LOG_REMINDER,
      ];
      ctx.ui.notify(lines.join("\n"), "info");
    },
  });
}
