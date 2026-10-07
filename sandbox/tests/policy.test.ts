import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readlinkSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  RESEARCHER_TOOL_ALLOWLIST,
  checkDefinition,
  checkLoadout,
  checkSpawn,
  findLoadout,
  renderResearcherDefinition,
  type LoadoutSnapshot,
  type ResearcherPolicy,
} from "../lib/policy.ts";
import { PANE_CLOSED_MESSAGE, PaneClosureWatch } from "../lib/closure.ts";
import { layout, mainPiArgs, validateProfile, type Profile } from "../lib/profile.ts";
import { configure } from "../bin/study-room-configure.ts";

function fixture() {
  const dir = mkdtempSync(join(tmpdir(), "sr-policy-"));
  const agentDir = join(dir, "agent");
  const cwd = join(dir, "Study Room");
  mkdirSync(join(agentDir, "agents"), { recursive: true });
  mkdirSync(cwd, { recursive: true });
  const trusted = renderResearcherDefinition({ model: "openai/gpt-x", thinking: "medium" });
  writeFileSync(join(agentDir, "agents", "researcher.md"), trusted);
  const policy: ResearcherPolicy = {
    model: "openai/gpt-x",
    thinking: "medium",
    allowedModelOverrides: ["openai/gpt-y"],
    trustedDefinition: trusted,
    agentDir,
  };
  return { dir, agentDir, cwd, policy, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

describe("spawn policy", () => {
  it("allows the researcher with the trusted model", () => {
    const f = fixture();
    try {
      assert.deepEqual(checkSpawn({ agent: "researcher", task: "t" }, f.policy, f.cwd), { allow: true });
      assert.deepEqual(checkSpawn({ agent: "researcher", task: "t", model: "openai/gpt-x" }, f.policy, f.cwd), { allow: true });
      assert.deepEqual(checkSpawn({ agent: "researcher", task: "t", model: "openai/gpt-y" }, f.policy, f.cwd), { allow: true }, "listed overrides are allowed");
    } finally {
      f.cleanup();
    }
  });
  for (const agent of ["scout", "worker", "planner", "", undefined, "Researcher", "researcher "]) {
    it(`rejects agent ${JSON.stringify(agent)}`, () => {
      const f = fixture();
      try {
        const d = checkSpawn({ agent, task: "t" }, f.policy, f.cwd);
        if (agent === "researcher ") assert.equal(d.allow, true, "surrounding whitespace is the same name");
        else assert.equal(d.allow, false);
      } finally {
        f.cleanup();
      }
    });
  }
  it("rejects unapproved model overrides and per-call thinking", () => {
    const f = fixture();
    try {
      for (const model of ["openai/gpt-z", "kimi-coding/k3", "gpt-x"]) {
        const d = checkSpawn({ agent: "researcher", task: "t", model }, f.policy, f.cwd);
        assert.equal(d.allow, false, model);
        assert.match((d as any).reason, /not approved/);
      }
      const d = checkSpawn({ agent: "researcher", task: "t", model: "openai/gpt-x:max" }, f.policy, f.cwd);
      assert.equal(d.allow, false);
      assert.match((d as any).reason, /thinking level/);
      assert.equal(checkSpawn({ agent: "researcher", task: "t", model: 42 }, f.policy, f.cwd).allow, false);
    } finally {
      f.cleanup();
    }
  });
  it("rejects a per-call working directory", () => {
    const f = fixture();
    try {
      assert.equal(checkSpawn({ agent: "researcher", task: "t", cwd: "/tmp" }, f.policy, f.cwd).allow, false);
    } finally {
      f.cleanup();
    }
  });
  it("rejects a project-local researcher that would shadow the trusted one", () => {
    const f = fixture();
    try {
      mkdirSync(join(f.cwd, ".pi", "agents"), { recursive: true });
      writeFileSync(join(f.cwd, ".pi", "agents", "researcher.md"), "---\nname: researcher\ntools: bash\n---\n");
      const d = checkSpawn({ agent: "researcher", task: "t" }, f.policy, f.cwd);
      assert.equal(d.allow, false);
      assert.match((d as any).reason, /project-local/);
    } finally {
      f.cleanup();
    }
  });
  it("rejects an edited or missing trusted definition", () => {
    const f = fixture();
    try {
      writeFileSync(join(f.agentDir, "agents", "researcher.md"), f.policy.trustedDefinition.replace("medium", "max"));
      assert.match((checkDefinition(f.policy, f.cwd) as any).reason, /differs/);
      rmSync(join(f.agentDir, "agents", "researcher.md"));
      assert.match((checkDefinition(f.policy, f.cwd) as any).reason, /missing/);
    } finally {
      f.cleanup();
    }
  });
});

describe("researcher definition", () => {
  it("has exactly the V1 researcher contract", () => {
    const text = renderResearcherDefinition({ model: "openai/gpt-x", thinking: "medium" });
    const front = text.split("---")[1];
    assert.match(front, /^name: researcher$/m);
    assert.match(front, /^model: openai\/gpt-x$/m);
    assert.match(front, /^thinking: medium$/m);
    assert.match(front, /^tools: web_search, web_fetch, safe_bash$/m);
    assert.match(front, /^auto-exit: true$/m);
    assert.ok(!/subagent_agents/.test(front), "the researcher cannot spawn children");
  });
  it("is independently authored, not Learn's researcher prose", () => {
    const text = renderResearcherDefinition({ model: "a/b", thinking: "medium" });
    const learnPath = join(process.env.STUDY_ROOM_ROOT || "/opt/study-room", "upstream", "learn", "agents", "researcher.md");
    if (!existsSync(learnPath)) return;
    const learn = readFileSync(learnPath, "utf8");
    const learnLines = new Set(learn.split("\n").map((l) => l.trim()).filter((l) => l.length > 30));
    const body = text.split("---").slice(2).join("---"); // prose only, not the frontmatter fields
    const shared = body.split("\n").map((l) => l.trim()).filter((l) => learnLines.has(l));
    assert.deepEqual(shared, []);
  });
});

describe("resume loadout", () => {
  const good = (policy: ResearcherPolicy): LoadoutSnapshot => ({
    agent: "researcher",
    toolAllowlist: RESEARCHER_TOOL_ALLOWLIST,
    model: policy.model,
    thinking: "medium",
    spawnable: null,
    cwd: null,
    agentDir: policy.agentDir,
  });
  it("accepts the original loadout", () => {
    const f = fixture();
    try {
      assert.deepEqual(checkLoadout(good(f.policy), f.policy), { allow: true });
    } finally {
      f.cleanup();
    }
  });
  const tamper: Array<[string, Partial<LoadoutSnapshot>]> = [
    ["agent", { agent: "worker" }],
    ["tools", { toolAllowlist: "bash,read,write" }],
    ["model", { model: "openai/gpt-z" }],
    ["thinking", { thinking: "max" }],
    ["spawning", { spawnable: ["researcher"] }],
    ["cwd", { cwd: "/" }],
    ["config dir", { agentDir: "/tmp/other" }],
  ];
  for (const [label, change] of tamper) {
    it(`refuses a loadout with a changed ${label}`, () => {
      const f = fixture();
      try {
        assert.equal(checkLoadout({ ...good(f.policy), ...change }, f.policy).allow, false);
      } finally {
        f.cleanup();
      }
    });
  }
  it("finds a loadout through the spawner's registry", () => {
    const f = fixture();
    try {
      const art = join(f.dir, "sessions", "artifacts", "sid");
      mkdirSync(art, { recursive: true });
      const sessionFile = join(f.dir, "child.jsonl");
      writeFileSync(join(art, "subagent-registry.json"), JSON.stringify({ "r-a": { sessionFile, sessionId: "x" } }));
      writeFileSync(`${sessionFile}.loadout.json`, JSON.stringify(good(f.policy)));
      assert.equal(findLoadout(join(f.dir, "sessions"), "sid", "r-a")?.agent, "researcher");
      assert.equal(findLoadout(join(f.dir, "sessions"), "sid", "missing"), null);
    } finally {
      f.cleanup();
    }
  });
});

describe("pane closure watch", () => {
  it("reports a run whose process disappears without a result", () => {
    const written: string[] = [];
    let live = [{ id: "%1", sessionFile: "/s/a.jsonl" }];
    const w = new PaneClosureWatch({ panes: () => live, writeExit: (f, m) => written.push(`${f}:${m}`) }, 1000, 5000);
    w.started("/s/a.jsonl", "r-a", 0);
    assert.deepEqual(w.tick(100), []);
    live = [];
    assert.deepEqual(w.tick(200), []);
    assert.deepEqual(w.tick(1199), []);
    assert.deepEqual(w.tick(1200), ["/s/a.jsonl"]);
    assert.deepEqual(written, [`/s/a.jsonl:${PANE_CLOSED_MESSAGE}`]);
    assert.equal(w.isTracked("/s/a.jsonl"), false);
  });
  it("does not report a run whose result was delivered", () => {
    const written: string[] = [];
    const w = new PaneClosureWatch({ panes: () => [], writeExit: (f) => written.push(f) }, 1000, 0);
    w.started("/s/b.jsonl", "r-b", 0);
    w.finished("/s/b.jsonl");
    assert.deepEqual(w.tick(10_000), []);
    assert.deepEqual(written, []);
  });
  it("waits for a run that is still launching", () => {
    const w = new PaneClosureWatch({ panes: () => [], writeExit: () => {} }, 1000, 5000);
    w.started("/s/c.jsonl", "r-c", 0);
    assert.deepEqual(w.tick(4000), []);
    assert.deepEqual(w.tick(5000), []);
    assert.deepEqual(w.tick(6000), ["/s/c.jsonl"], "a run never seen is reported after the startup allowance");
  });
});

function profile(workspace: string): Profile {
  return {
    schema: 1,
    installation_id: "i",
    network_mode: "balanced",
    workspace,
    main: { provider: "openai", pi_provider: "openai", model: "gpt-x", thinking: "max", thinking_fallback: null },
    researcher: { provider: "openai", pi_provider: "openai", model: "gpt-x", thinking: "medium", allowed_model_overrides: [] },
    search: { provider: "openai", pi_provider: "openai", model: "gpt-s" },
    providers: { openai: { enabled: true, experimental: false, verified: false } },
    host_summary: [],
    warnings: [],
    lock_fingerprint: "f",
  };
}

describe("profile", () => {
  it("validates provider mapping, thinking and model ids", () => {
    const p = profile("/vault/Study Room");
    assert.ok(validateProfile(p));
    assert.throws(() => validateProfile({ ...p, network_mode: "open" }));
    assert.throws(() => validateProfile({ ...p, main: { ...p.main, pi_provider: "kimi-coding" } }));
    assert.throws(() => validateProfile({ ...p, main: { ...p.main, model: "openai/gpt-x" } }));
    assert.throws(() => validateProfile({ ...p, researcher: { ...p.researcher, thinking: "huge" } }));
    assert.throws(() => validateProfile({ ...p, workspace: "relative" }));
  });
  it("loads only the approved Learn resources, explicitly, with discovery off", () => {
    const l = layout("/home/agent", "/opt/study-room");
    const args = mainPiArgs(profile("/w"), l, "max");
    const joined = args.join(" ");
    assert.ok(args.includes("--no-extensions") && args.includes("--no-skills") && args.includes("--no-approve"));
    for (const r of ["extensions/ask-user-question.ts", "extensions/quiz.ts", "extensions/md-log.ts", "skills/teach"]) {
      assert.ok(joined.includes(`/opt/study-room/upstream/learn/${r}`), r);
    }
    for (const r of ["visualize", "visual-tools", "learn/agents"]) assert.ok(!joined.includes(r), `${r} is not loaded`);
    assert.ok(joined.includes("pi-interactive-subagents/pi-extension/subagents/index.ts"));
    assert.ok(joined.includes("study-room-guard/index.ts"));
    assert.deepEqual(args.slice(args.indexOf("--model"), args.indexOf("--model") + 2), ["--model", "openai/gpt-x"]);
    assert.deepEqual(args.slice(-2), ["--thinking", "max"]);
  });
});

describe("configure", () => {
  it("writes the profile, the trusted researcher and the /workspace link", () => {
    const dir = mkdtempSync(join(tmpdir(), "sr-conf-"));
    try {
      const ws = join(dir, "vault", "Study Room");
      mkdirSync(ws, { recursive: true });
      const root = join(dir, "root");
      const link = join(dir, "workspace");
      configure(JSON.stringify(profile(ws)), root, link);
      assert.equal(JSON.parse(readFileSync(join(root, "etc", "profile.json"), "utf8")).workspace, ws);
      assert.match(readFileSync(join(root, "etc", "agents", "researcher.md"), "utf8"), /model: openai\/gpt-x/);
      assert.equal(readlinkSync(link), ws);
      configure(JSON.stringify(profile(ws)), root, link); // idempotent
      assert.ok(lstatSync(link).isSymbolicLink());
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
  it("refuses when the workspace is not mounted or the link path is a real directory", () => {
    const dir = mkdtempSync(join(tmpdir(), "sr-conf-"));
    try {
      assert.throws(() => configure(JSON.stringify(profile(join(dir, "missing"))), join(dir, "root"), join(dir, "ws")), /not mounted/);
      const ws = join(dir, "Study Room");
      mkdirSync(ws);
      mkdirSync(join(dir, "realdir"));
      assert.throws(() => configure(JSON.stringify(profile(ws)), join(dir, "root"), join(dir, "realdir")), /not a symlink/);
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});
