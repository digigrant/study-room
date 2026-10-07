// tmux pane bookkeeping for researcher lifecycle cleanup (SPEC 11.4).
//
// pi-interactive-subagents does not name its panes, so a researcher pane is
// recognised by the process running in it: a descendant of the pane's shell
// whose environment carries PI_SUBAGENT_AGENT=researcher (set by the package
// when it launches the child).

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";

export const SESSION = "study-room";
export const MAIN_ROLE = "main";

export interface Pane {
  id: string;
  pid: number;
  role: string;
  dead: boolean;
}

function tmux(args: string[]): string {
  return execFileSync("tmux", args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] });
}

export function listPanes(session = SESSION): Pane[] {
  let out: string;
  try {
    out = tmux(["list-panes", "-s", "-t", session, "-F", "#{pane_id}|#{pane_pid}|#{@study-room-role}|#{pane_dead}"]);
  } catch {
    return [];
  }
  return out
    .split("\n")
    .filter(Boolean)
    .map((line) => {
      const [id, pid, role, dead] = line.split("|");
      return { id, pid: Number(pid), role: role ?? "", dead: dead === "1" };
    });
}

function childrenMap(): Map<number, number[]> {
  const map = new Map<number, number[]>();
  for (const name of readdirSync("/proc")) {
    if (!/^\d+$/.test(name)) continue;
    try {
      const stat = readFileSync(`/proc/${name}/stat`, "utf8");
      // pid (comm) state ppid ...; comm may contain spaces/parens.
      const ppid = Number(stat.slice(stat.lastIndexOf(")") + 2).split(" ")[1]);
      const list = map.get(ppid) ?? [];
      list.push(Number(name));
      map.set(ppid, list);
    } catch {
      // process exited
    }
  }
  return map;
}

export function descendants(pid: number, map = childrenMap()): number[] {
  const out: number[] = [];
  const stack = [pid];
  while (stack.length) {
    const p = stack.pop()!;
    for (const c of map.get(p) ?? []) {
      out.push(c);
      stack.push(c);
    }
  }
  return out;
}

export function environ(pid: number): Record<string, string> {
  try {
    const raw = readFileSync(`/proc/${pid}/environ`, "utf8");
    const env: Record<string, string> = {};
    for (const entry of raw.split("\0")) {
      const i = entry.indexOf("=");
      if (i > 0) env[entry.slice(0, i)] = entry.slice(i + 1);
    }
    return env;
  } catch {
    return {};
  }
}

export interface SubagentPane extends Pane {
  agent: string;
  subagentId: string;
  sessionFile: string;
}

export function subagentPanes(session = SESSION): SubagentPane[] {
  const map = childrenMap();
  const out: SubagentPane[] = [];
  for (const pane of listPanes(session)) {
    if (pane.role === MAIN_ROLE) continue;
    for (const pid of [pane.pid, ...descendants(pane.pid, map)]) {
      const env = environ(pid);
      if (env.PI_SUBAGENT_AGENT) {
        out.push({ ...pane, agent: env.PI_SUBAGENT_AGENT, subagentId: env.PI_SUBAGENT_ID ?? "", sessionFile: env.PI_SUBAGENT_SESSION ?? "" });
        break;
      }
    }
  }
  return out;
}

/** Kill researcher panes (orphans after a parent exit or restart). Returns killed pane ids. */
export function killSubagentPanes(session = SESSION): string[] {
  const killed: string[] = [];
  for (const pane of subagentPanes(session)) {
    try {
      tmux(["kill-pane", "-t", pane.id]);
      killed.push(pane.id);
    } catch {
      // already gone
    }
  }
  return killed;
}

export function markMainPane(paneId: string | undefined): void {
  if (!paneId) return;
  try {
    tmux(["set-option", "-p", "-t", paneId, "@study-room-role", MAIN_ROLE]);
  } catch {
    // not inside tmux
  }
}
