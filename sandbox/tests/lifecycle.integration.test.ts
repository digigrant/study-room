// Researcher lifecycle in real tmux with real Pi processes and a fake
// provider (SPEC 11.4, 20.1). Runs inside the sandbox image, where the pinned
// runtime and upstream checkouts exist:
//   /opt/study-room/bin/study-room-selftest --integration
// No credential, provider, GitHub or vault is used: the provider is a local
// scripted server and the "vault" is a temporary directory.

import { after, before, describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { FakeProvider, modelsJson, type LoggedRequest, type Reply } from "./helpers/fake-provider.ts";
import { configure } from "../bin/study-room-configure.ts";
import { prepare, prepareAgentDir } from "../bin/study-room-entry.ts";
import { layout, type Profile } from "../lib/profile.ts";

const REAL_ROOT = process.env.STUDY_ROOM_ROOT || "/opt/study-room";
const PLACEHOLDER = "sr-openai-PLACEHOLDER-0000";

function hasTmux(): boolean {
  return spawnSync("tmux", ["-V"], { stdio: "ignore" }).status === 0;
}
const runtimeReady =
  existsSync(join(REAL_ROOT, "runtime", "node_modules", "@earendil-works", "pi-coding-agent", "package.json")) &&
  existsSync(join(REAL_ROOT, "upstream", "learn", "skills", "teach")) &&
  existsSync(join(REAL_ROOT, "upstream", "pi-interactive-subagents", "pi-extension"));
const skip = !hasTmux()
  ? "tmux is not installed"
  : !runtimeReady
    ? `the pinned runtime is not installed at ${REAL_ROOT} (run inside the sandbox image)`
    : false;

function teacher(req: LoggedRequest): Reply {
  const last = req.last;
  if (last.role === "tool") return { text: `TOOLRESULT ${last.text.slice(0, 400)}` };
  const t = last.text;
  if (t.includes('Sub-agent "')) return { text: `ACK ${t.replace(/\s+/g, " ").slice(0, 300)}` };
  const m = /CMD:(\w+)(?::(\S+))?/.exec(t);
  if (!m) return { text: "ok" };
  const [, cmd, arg] = m;
  switch (cmd) {
    case "SPAWN":
      return { tool: { name: "subagent", args: { agent: "researcher", name: `r-${arg}`, task: `Research topic ${arg}` } } };
    case "SCOUT":
      return { tool: { name: "subagent", args: { agent: "scout", task: "look around" } } };
    case "OVERRIDE":
      return { tool: { name: "subagent", args: { agent: "researcher", name: "r-override", model: "openai/gpt-5.5", task: "Research topic override" } } };
    case "CWD":
      return { tool: { name: "subagent", args: { agent: "researcher", name: "r-cwd", cwd: "/tmp", task: "Research topic cwd" } } };
    case "RESUME":
      return { tool: { name: "subagent_message", args: { name: arg, message: "Follow up please" } } };
    case "PING":
      return { text: `PONG ${arg}` };
  }
  return { text: "unknown" };
}

function researcher(req: LoggedRequest): Reply {
  const all = req.messages.filter((m) => m.role === "user").map((m) => m.text).join("\n");
  const id = /Research topic (\S+)/.exec(all)?.[1] ?? "unknown";
  if (req.last.role === "user" && req.last.text.includes("Follow up please")) return { text: `RESUMED ${id}` };
  if (id.startsWith("HANG")) return { hang: true };
  const answer = `## Answer\nRESEARCH-DONE ${id} [Source](https://example.org/${id})`;
  if (id.startsWith("SLOW")) return { text: answer, delayMs: 6000 };
  return { text: answer };
}

async function waitFor<T>(what: string, fn: () => T | undefined | false | null, timeoutMs = 30_000): Promise<T> {
  const start = Date.now();
  for (;;) {
    const v = fn();
    if (v) return v as T;
    if (Date.now() - start > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await new Promise((r) => setTimeout(r, 200));
  }
}

class Harness {
  readonly tmp = mkdtempSync(join(tmpdir(), "sr-life-"));
  readonly home = join(this.tmp, "home");
  readonly vault = join(this.tmp, "vault");
  readonly workspace = join(this.vault, "Study Room");
  readonly root = join(this.tmp, "root");
  readonly socket = `sr-test-${process.pid}-${Math.random().toString(16).slice(2, 8)}`;
  readonly provider = new FakeProvider({ "fake-teacher": teacher, "fake-researcher": researcher });
  args: string[] = [];
  env: Record<string, string> = {};

  async setup(): Promise<void> {
    mkdirSync(this.home, { recursive: true });
    mkdirSync(this.workspace, { recursive: true });
    mkdirSync(join(this.root, "etc"), { recursive: true });
    for (const d of ["runtime", "node", "upstream", "lib", "extensions", "bin", "tests", "node_modules"]) {
      if (existsSync(join(REAL_ROOT, d))) symlinkSync(join(REAL_ROOT, d), join(this.root, d));
    }
    const port = await this.provider.start();
    const profile: Profile = {
      schema: 1,
      installation_id: "00000000-0000-4000-8000-000000000000",
      network_mode: "balanced",
      workspace: this.workspace,
      main: { provider: "openai", pi_provider: "openai", model: "fake-teacher", thinking: "max", thinking_fallback: null },
      researcher: { provider: "openai", pi_provider: "openai", model: "fake-researcher", thinking: "medium", allowed_model_overrides: [] },
      search: { provider: null, pi_provider: null, model: null },
      providers: { openai: { enabled: true, experimental: false, verified: false } },
      host_summary: ["test host"],
      warnings: [],
      lock_fingerprint: "test",
    };
    configure(JSON.stringify(profile), this.root, join(this.tmp, "workspace-link"));
    const l = layout(this.home, this.root);
    prepareAgentDir(profile, l);
    writeFileSync(join(l.agentDir, "models.json"), modelsJson(port, ["fake-teacher", "fake-researcher"]));
    const prepared = await prepare(profile, l);
    this.args = prepared.args;
    this.env = {
      ...(process.env as Record<string, string>),
      ...prepared.env,
      HOME: this.home,
      STUDY_ROOM_ROOT: this.root,
      OPENAI_API_KEY: PLACEHOLDER,
      TERM: "xterm-256color",
      PI_SUBAGENT_SHELL_READY_DELAY_MS: "800",
    };
    delete this.env.TMUX;
    delete this.env.TMUX_PANE;
    for (const k of ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"]) delete this.env[k];
  }

  tmux(args: string[]): string {
    return execFileSync("tmux", ["-L", this.socket, ...args], { encoding: "utf8", env: this.env, stdio: ["ignore", "pipe", "pipe"] });
  }

  startMain(newWindow = false): void {
    const cmd = ["pi", ...this.args];
    if (newWindow) this.tmux(["new-window", "-t", "study-room", "-c", this.workspace, "--", ...cmd]);
    else this.tmux(["-f", "/dev/null", "new-session", "-d", "-s", "study-room", "-x", "220", "-y", "60", "-c", this.workspace, "--", ...cmd]);
  }

  panes(): Array<{ id: string; pid: number; role: string; dead: boolean }> {
    try {
      return this.tmux(["list-panes", "-s", "-t", "study-room", "-F", "#{pane_id}|#{pane_pid}|#{@study-room-role}|#{pane_dead}"])
        .trim()
        .split("\n")
        .filter(Boolean)
        .map((l) => {
          const [id, pid, role, dead] = l.split("|");
          return { id, pid: Number(pid), role, dead: dead === "1" };
        });
    } catch {
      return [];
    }
  }

  screen(): string {
    try {
      return this.panes()
        .map((p) => `--- pane ${p.id} (${p.role || "?"}${p.dead ? ", dead" : ""}) ---\n${this.tmux(["capture-pane", "-p", "-t", p.id]).trimEnd()}`)
        .join("\n");
    } catch (err: any) {
      return `(no tmux session: ${err?.message ?? err})`;
    }
  }

  async mainPane(): Promise<string> {
    try {
      return (await waitFor("the main pane to be marked by the guard", () => this.panes().find((p) => p.role === "main" && !p.dead)?.id, 40_000)) as string;
    } catch (err: any) {
      throw new Error(`${err.message}\n${this.screen()}`);
    }
  }

  async send(text: string): Promise<void> {
    const pane = await this.mainPane();
    this.tmux(["send-keys", "-t", pane, "-l", text]);
    await new Promise((r) => setTimeout(r, 150));
    this.tmux(["send-keys", "-t", pane, "Enter"]);
  }

  /** Wait helper that appends the tmux screen to a timeout error. */
  async until<T>(what: string, fn: () => T | undefined | false | null, timeoutMs = 30_000): Promise<T> {
    try {
      return await waitFor(what, fn, timeoutMs);
    } catch (err: any) {
      throw new Error(`${err.message}\n${this.screen()}\n--- provider log ---\n${this.provider.log.map((r) => `${r.model} ${r.last.role}: ${r.last.text.slice(0, 160).replace(/\s+/g, " ")}`).join("\n")}`);
    }
  }

  researcherPids(name?: string): number[] {
    const out: number[] = [];
    for (const p of readdirSync("/proc")) {
      if (!/^\d+$/.test(p)) continue;
      try {
        const env = readFileSync(`/proc/${p}/environ`, "utf8").split("\0");
        const cmd = readFileSync(`/proc/${p}/cmdline`, "utf8");
        // Pi sets its process title to "pi"; skip the launch shells around it.
        if (/^(-?bash|sh)\b/.test(cmd.replace(/\0/g, " "))) continue;
        if (env.includes("PI_SUBAGENT_AGENT=researcher") && (!name || env.includes(`PI_SUBAGENT_NAME=${name}`)) && env.includes(`HOME=${this.home}`)) out.push(Number(p));
      } catch {
        // gone
      }
    }
    return out;
  }

  /** The steered result message for a named researcher, once delivered. */
  resultFor(name: string): LoggedRequest | undefined {
    return this.provider.log.find((r) => r.model === "fake-teacher" && r.last.role === "user" && r.last.text.includes(`Sub-agent "${name}"`));
  }

  researcherPane(): string | undefined {
    return this.panes().find((p) => p.role !== "main" && !p.dead)?.id;
  }

  kill(): void {
    try {
      this.tmux(["kill-server"]);
    } catch {
      // not running
    }
  }

  async teardown(): Promise<void> {
    this.kill();
    await this.provider.stop();
    rmSync(this.tmp, { recursive: true, force: true });
  }
}

describe("researcher lifecycle (tmux, fake provider)", { skip, timeout: 300_000 }, () => {
  const h = new Harness();
  before(async () => {
    await h.setup();
    h.startMain();
    await h.mainPane();
  });
  after(async () => {
    await h.teardown();
  });

  it("spawns the researcher, which completes and steers its result to the parent", async () => {
    await h.send("CMD:SPAWN:alpha");
    await h.until("the researcher result to reach the parent", () => h.provider.sawText("RESEARCH-DONE alpha", "fake-teacher"), 60_000);
    const child = h.provider.requestsFor("fake-researcher")[0];
    assert.ok(child, "the researcher made a model request");
    for (const tool of ["web_search", "web_fetch", "safe_bash"]) assert.ok(child.tools.includes(tool), `researcher has ${tool}`);
    for (const tool of ["bash", "read", "write", "edit", "subagent", "subagent_message"]) assert.ok(!child.tools.includes(tool), `researcher lacks ${tool}`);
    assert.match(child.system, /researcher for a one-learner study session/);
    assert.equal(child.auth, `Bearer ${PLACEHOLDER}`, "only the placeholder credential is used");
    await h.until("the researcher pane to close", () => !h.researcherPane(), 20_000);
  });

  it("gives the main session the study tools and the subagent tools", () => {
    const main = h.provider.requestsFor("fake-teacher")[0];
    for (const tool of ["read", "bash", "edit", "write", "subagent", "ask_user_question", "quiz"]) {
      assert.ok(main.tools.includes(tool), `main session has ${tool} (has ${main.tools.join(", ")})`);
    }
    assert.ok(!main.tools.includes("web_fetch"), "research tools belong to the researcher");
    assert.match(main.system, /teach/i, "the teach skill is advertised");
    assert.ok(!/visualize/i.test(main.system), "the visualize skill is not loaded");
  });

  it("keeps the parent responsive while a researcher runs, with status updates", async () => {
    await h.send("CMD:SPAWN:SLOW-beta");
    await h.until("the slow researcher to start", () => h.provider.requestsFor("fake-researcher").some((r) => r.messages.some((m) => m.text.includes("SLOW-beta"))), 30_000);
    const activity = await h.until("an activity snapshot from the running researcher", () => {
      const found = execFileSync("find", [join(h.home, ".study-room"), "-path", "*subagent-activity*", "-type", "f"], { encoding: "utf8" }).trim();
      return found || undefined;
    }, 10_000);
    assert.ok(activity.length > 0, "the child writes status snapshots for the parent's widget");
    await h.send("CMD:PING:1");
    const pong = await h.until("the parent to answer while the researcher works", () => h.provider.log.find((r) => r.model === "fake-teacher" && r.last.text.includes("CMD:PING:1")), 20_000);
    assert.ok(!h.provider.sawText("RESEARCH-DONE SLOW-beta", "fake-teacher"), "the parent answered before the result arrived");
    await h.until("the slow result", () => h.provider.sawText("RESEARCH-DONE SLOW-beta", "fake-teacher"), 40_000);
    assert.ok(pong.at > 0);
  });

  it("rejects non-researcher roles", async () => {
    await h.send("CMD:SCOUT");
    await h.until("the scout rejection", () => h.provider.log.find((r) => r.model === "fake-teacher" && r.last.role === "tool" && /scout/.test(r.last.text)), 20_000);
    const rejection = h.provider.log.filter((r) => r.model === "fake-teacher" && r.last.role === "tool").at(-1)!;
    assert.match(rejection.last.text, /only the "researcher" subagent may be launched|not in your allowlist/);
  });

  it("rejects unapproved model overrides and working-directory overrides", async () => {
    await h.send("CMD:OVERRIDE");
    await h.until("the override rejection", () => h.provider.log.find((r) => r.model === "fake-teacher" && r.last.role === "tool" && r.last.text.includes("model override")), 20_000);
    await h.send("CMD:CWD");
    await h.until("the cwd rejection", () => h.provider.log.find((r) => r.model === "fake-teacher" && r.last.role === "tool" && r.last.text.includes("working directory")), 20_000);
    assert.ok(!h.provider.sawText("Research topic override", "fake-researcher"));
    assert.ok(!h.provider.sawText("Research topic cwd", "fake-researcher"));
  });

  it("resumes a finished researcher with its original loadout", async () => {
    const before = h.provider.requestsFor("fake-researcher").length;
    await h.send("CMD:RESUME:r-alpha");
    await h.until("the resumed researcher answer", () => h.provider.sawText("RESUMED alpha", "fake-teacher"), 60_000);
    const resumed = h.provider.requestsFor("fake-researcher").slice(before).find((r) => r.last.text.includes("Follow up please"));
    assert.ok(resumed, "the resumed child called the provider");
    assert.deepEqual([...resumed!.tools].sort(), [...h.provider.requestsFor("fake-researcher")[0].tools].sort(), "same tool loadout");
    await h.until("the resumed pane to close", () => !h.researcherPane(), 20_000);
  });

  it("refuses to resume from a tampered loadout snapshot", async () => {
    const files = execFileSync("find", [join(h.home, ".study-room"), "-name", "*.loadout.json"], { encoding: "utf8" }).trim().split("\n");
    const target = files.find((f) => readFileSync(f, "utf8").includes("fake-researcher"))!;
    const loadout = JSON.parse(readFileSync(target, "utf8"));
    loadout.toolAllowlist = "bash,read,write";
    writeFileSync(target, JSON.stringify(loadout));
    // The registry maps r-alpha to the most recent session; tamper both if needed.
    for (const f of files) {
      const l = JSON.parse(readFileSync(f, "utf8"));
      l.toolAllowlist = "bash,read,write";
      writeFileSync(f, JSON.stringify(l));
    }
    await h.send("CMD:RESUME:r-alpha");
    await h.until("the tampered-resume rejection", () => h.provider.log.find((r) => r.model === "fake-teacher" && r.last.role === "tool" && r.last.text.includes("resume refused")), 20_000);
  });

  it("reports a cancelled researcher to the parent and closes its pane", async () => {
    await h.send("CMD:SPAWN:HANG-cancel");
    const [pid] = await h.until("the researcher process", () => {
      const p = h.researcherPids("r-HANG-cancel");
      return p.length ? p : undefined;
    }, 30_000);
    await h.until("the researcher request", () => h.provider.sawText("HANG-cancel", "fake-researcher"), 30_000);
    process.kill(pid, "SIGTERM"); // an orderly stop from outside the researcher
    await h.until("the cancelled researcher to exit", () => h.researcherPids("r-HANG-cancel").length === 0, 20_000);
    await h.until("the parent to hear about it", () => h.resultFor("r-HANG-cancel"), 30_000);
    await h.until("the cancelled pane to close", () => !h.researcherPane(), 20_000);
  });

  it("reports a crashed researcher", async () => {
    await h.send("CMD:SPAWN:HANG-crash");
    const [pid] = await h.until("the researcher process", () => {
      const p = h.researcherPids("r-HANG-crash");
      return p.length ? p : undefined;
    }, 30_000);
    await h.until("the researcher request", () => h.provider.sawText("HANG-crash", "fake-researcher"), 30_000);
    process.kill(pid, "SIGKILL");
    const msg = await h.until("the crash report", () => h.resultFor("r-HANG-crash"), 30_000);
    assert.match(msg.last.text, /failed \(exit code 137\)/);
  });

  it("reports a researcher whose tmux pane was closed", async () => {
    await h.send("CMD:SPAWN:HANG-pane");
    await h.until("the researcher request", () => h.provider.sawText("HANG-pane", "fake-researcher"), 30_000);
    const pane = await h.until("the researcher pane", () => h.researcherPane(), 10_000);
    h.tmux(["kill-pane", "-t", pane]);
    const msg = await h.until("the pane-closure report", () => h.resultFor("r-HANG-pane"), 40_000);
    assert.match(msg.last.text, /failed/);
    await h.until("the researcher process to be gone", () => h.researcherPids("r-HANG-pane").length === 0, 20_000);
  });

  it("never writes sessions or artifacts into the vault", () => {
    assert.deepEqual(readdirSync(h.workspace), [], "Study Room/ is untouched by sessions, artifacts and loadouts");
    assert.deepEqual(readdirSync(h.vault), ["Study Room"]);
    assert.ok(existsSync(join(h.home, ".study-room", "sessions")), "sessions live in sandbox-local disposable state");
  });
});

describe("parent exit and orphan cleanup", { skip, timeout: 240_000 }, () => {
  it("stops running researchers when the parent quits", async () => {
    const h = new Harness();
    try {
      await h.setup();
      h.startMain();
      await h.send("CMD:SPAWN:HANG-quit");
      await h.until("the researcher", () => h.researcherPids("r-HANG-quit").length > 0, 30_000);
      await h.until("the researcher request", () => h.provider.sawText("HANG-quit", "fake-researcher"), 30_000);
      await h.send("/quit");
      await h.until("the researcher to be stopped with its parent", () => h.researcherPids("r-HANG-quit").length === 0, 30_000);
    } finally {
      await h.teardown();
    }
  });

  it("closes orphaned researchers when a new main session starts", async () => {
    const h = new Harness();
    try {
      await h.setup();
      h.startMain();
      const mainPane = await h.mainPane();
      await h.send("CMD:SPAWN:HANG-orphan");
      await h.until("the researcher", () => h.researcherPids("r-HANG-orphan").length > 0, 30_000);
      await h.until("the researcher request", () => h.provider.sawText("HANG-orphan", "fake-researcher"), 30_000);
      // Kill the parent without letting it clean up.
      const mainPid = Number(h.tmux(["display-message", "-p", "-t", mainPane, "#{pane_pid}"]).trim());
      const before = `${h.screen()}\nresearcher pids ${h.researcherPids("r-HANG-orphan")} main ${mainPid}\n${execFileSync("ps", ["-eo", "pid,ppid,pgid,sid,args"], { encoding: "utf8" })}`;
      process.kill(mainPid, "SIGKILL");
      await h.until("the main pane to go", () => !h.panes().some((p) => p.id === mainPane && !p.dead), 10_000);
      await new Promise((r) => setTimeout(r, 500));
      assert.ok(h.researcherPids("r-HANG-orphan").length > 0, `the researcher is now an orphan\nBEFORE:\n${before}\nAFTER:\n${h.screen()}\n${execFileSync("ps", ["-eo", "pid,ppid,pgid,sid,args"], { encoding: "utf8" })}`);
      h.startMain(true);
      await h.until("the new main session to close the orphan", () => h.researcherPids("r-HANG-orphan").length === 0, 40_000);
    } finally {
      await h.teardown();
    }
  });
});
