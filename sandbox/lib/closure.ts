// Detects researcher runs whose process disappears without reporting back,
// for example because their tmux pane was closed.
//
// A run is tracked from its "started" tool result until its subagent_result
// message. pi-interactive-subagents learns that a run ended by reading the
// exit sentinel from the run's pane; if the pane is gone, it would wait
// forever. When a tracked run has no live researcher process for a grace
// period (the package needs about a second to read a normal exit, close the
// pane and deliver the result), the watch reports the run through the
// package's own `.exit` sidecar so the parent hears about it.

export const PANE_CLOSED_GRACE_MS = 6000;
export const STARTUP_GRACE_MS = 15000;
export const PANE_CLOSED_MESSAGE = "The researcher's tmux pane was closed before it returned a result.";

interface Run {
  name: string;
  startedAt: number;
  seen: boolean;
  goneSince: number | null;
}

export interface ClosureDeps {
  /** Live researcher processes in the session, keyed by their session file. */
  panes: () => Array<{ id: string; sessionFile: string }>;
  writeExit: (sessionFile: string, message: string) => void;
}

export class PaneClosureWatch {
  private readonly runs = new Map<string, Run>();
  private readonly deps: ClosureDeps;
  private readonly graceMs: number;
  private readonly startupMs: number;

  constructor(deps: ClosureDeps, graceMs = PANE_CLOSED_GRACE_MS, startupMs = STARTUP_GRACE_MS) {
    this.deps = deps;
    this.graceMs = graceMs;
    this.startupMs = startupMs;
  }

  started(sessionFile: string, name: string, now = Date.now()): void {
    this.runs.set(sessionFile, { name, startedAt: now, seen: false, goneSince: null });
  }

  finished(sessionFile: string): void {
    this.runs.delete(sessionFile);
  }

  isTracked(sessionFile: string): boolean {
    return this.runs.has(sessionFile);
  }

  clear(): void {
    this.runs.clear();
  }

  /** Returns the session files reported in this tick. */
  tick(now: number): string[] {
    if (!this.runs.size) return [];
    const live = new Set(this.deps.panes().map((p) => p.sessionFile));
    const reported: string[] = [];
    for (const [sessionFile, run] of this.runs) {
      if (live.has(sessionFile)) {
        run.seen = true;
        run.goneSince = null;
        continue;
      }
      if (!run.seen && now - run.startedAt < this.startupMs) continue; // still launching
      run.goneSince ??= now;
      if (now - run.goneSince >= this.graceMs) {
        this.deps.writeExit(sessionFile, PANE_CLOSED_MESSAGE);
        this.runs.delete(sessionFile);
        reported.push(sessionFile);
      }
    }
    return reported;
  }
}
