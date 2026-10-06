// Pinned-runtime compatibility (SPEC 10.1, 10.3, 11.1):
// * Learn and pi-interactive-subagents are unmodified, clean checkouts at
//   their pinned commits, read-only for normal use;
// * every module they import is a Node builtin, a relative file, or a module
//   the pinned Pi supplies through its virtual module map (the legacy
//   @mariozechner/* and @sinclair/typebox aliases). A Pi bump that drops an
//   alias fails here instead of tempting a source patch;
// * the subagent package's own unit tests pass unmodified on the pinned Node,
//   run through an external loader that supplies the same aliases.

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { accessSync, constants, cpSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from "node:fs";
import { builtinModules } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";

const ROOT = process.env.STUDY_ROOM_ROOT || "/opt/study-room";
const LEARN = join(ROOT, "upstream", "learn");
const SUBAGENTS = join(ROOT, "upstream", "pi-interactive-subagents");
const PI = join(ROOT, "runtime", "node_modules", "@earendil-works", "pi-coding-agent");
const skip = existsSync(join(PI, "package.json")) && existsSync(LEARN) && existsSync(SUBAGENTS) ? false : "the pinned runtime and checkouts are not installed here (run inside the sandbox image)";

function build(): any {
  return JSON.parse(readFileSync(join(ROOT, "etc", "build.json"), "utf8"));
}

function tsFiles(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    if (name === ".git" || name === "node_modules") continue;
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...tsFiles(p));
    else if (/\.(ts|mts|js|mjs)$/.test(name)) out.push(p);
  }
  return out;
}

function bareImports(file: string): string[] {
  const src = readFileSync(file, "utf8");
  const specs = new Set<string>();
  for (const re of [/\bfrom\s+["']([^"']+)["']/g, /\bimport\s*\(\s*["']([^"']+)["']\s*\)/g, /\bimport\s+["']([^"']+)["']/g]) {
    let m: RegExpExecArray | null;
    while ((m = re.exec(src))) specs.add(m[1]);
  }
  return [...specs].filter((s) => !s.startsWith(".") && !s.startsWith("/"));
}

function piVirtualModules(): Set<string> {
  const src = readFileSync(join(PI, "dist", "core", "extensions", "virtual-modules.js"), "utf8");
  const keys = new Set<string>();
  const block = src.slice(src.indexOf("VIRTUAL_MODULES"));
  for (const m of block.matchAll(/^\s*"?([@a-z0-9/._-]+)"?\s*:/gim)) keys.add(m[1]);
  return keys;
}

describe("pinned upstream checkouts", { skip }, () => {
  for (const name of ["learn", "pi-interactive-subagents"]) {
    it(`${name} is the pinned, clean, unmodified checkout`, () => {
      const src = build().upstream[name];
      const out = execFileSync(join(ROOT, "bin", "verify-checkout.sh"), [src.dir, src.url, src.commit, src.tree], { encoding: "utf8" });
      assert.match(out, /ok/);
    });
    it(`${name} is read-only for normal use`, () => {
      const dir = build().upstream[name].dir;
      assert.equal(statSync(dir).uid, 0, "root-owned");
      assert.throws(() => accessSync(dir, constants.W_OK), "not writable");
      assert.throws(() => writeFileSync(join(dir, "probe"), "x"));
    });
  }
});

describe("legacy import compatibility", { skip }, () => {
  const virtual = skip ? new Set<string>() : piVirtualModules();
  const files = skip
    ? []
    : [
        join(LEARN, "extensions", "ask-user-question.ts"),
        join(LEARN, "extensions", "quiz.ts"),
        join(LEARN, "extensions", "md-log.ts"),
        ...tsFiles(join(SUBAGENTS, "pi-extension")),
      ];
  it("Pi still provides the @mariozechner/* and @sinclair/typebox aliases", () => {
    for (const alias of ["@mariozechner/pi-coding-agent", "@mariozechner/pi-tui", "@mariozechner/pi-ai", "@mariozechner/pi-agent-core", "@sinclair/typebox"]) {
      assert.ok(virtual.has(alias), `${alias} is supplied by the pinned Pi`);
    }
  });
  it("every import of the loaded upstream code resolves without patching", () => {
    const builtins = new Set([...builtinModules, ...builtinModules.map((m) => `node:${m}`)]);
    const unresolved: string[] = [];
    for (const file of files) {
      for (const spec of bareImports(file)) {
        if (builtins.has(spec) || spec.startsWith("node:") || virtual.has(spec)) continue;
        unresolved.push(`${file}: ${spec}`);
      }
    }
    assert.deepEqual(unresolved, []);
  });
  it("Pi loads the approved Learn extensions and the subagent extension", () => {
    const tmp = mkdtempSync(join(tmpdir(), "sr-compat-"));
    try {
      const r = spawnSync(
        join(ROOT, "bin", "pi"),
        [
          "--no-extensions",
          "-e", join(LEARN, "extensions", "ask-user-question.ts"),
          "-e", join(LEARN, "extensions", "quiz.ts"),
          "-e", join(LEARN, "extensions", "md-log.ts"),
          "-e", join(SUBAGENTS, "pi-extension", "subagents", "index.ts"),
          "--help",
        ],
        { encoding: "utf8", env: { ...process.env, PI_CODING_AGENT_DIR: tmp, PI_OFFLINE: "1", PI_SKIP_VERSION_CHECK: "1", HOME: tmp }, timeout: 60_000 },
      );
      const output = `${r.stdout}\n${r.stderr}`;
      assert.equal(r.status, 0, output);
      assert.ok(!/failed to load|error loading|cannot find module/i.test(output), output);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});

describe("subagent package's own tests", { skip }, () => {
  it("pass unmodified on the pinned Node through an external alias loader", () => {
    // Run on a disposable copy so the read-only checkout stays untouched.
    const tmp = mkdtempSync(join(tmpdir(), "sr-upstream-"));
    try {
      const copy = join(tmp, "pi-interactive-subagents");
      cpSync(SUBAGENTS, copy, { recursive: true });
      execFileSync("chmod", ["-R", "u+w", copy]);
      const nested = (pkg: string) => join(PI, "node_modules", ...pkg.split("/"));
      const aliases: Record<string, string> = {
        "@mariozechner/pi-coding-agent": join(PI, "dist", "index.js"),
        "@mariozechner/pi-tui": join(nested("@earendil-works/pi-tui"), "dist", "index.js"),
        "@mariozechner/pi-ai": join(nested("@earendil-works/pi-ai"), "dist", "index.js"),
        "@sinclair/typebox": join(nested("typebox"), "build", "index.mjs"),
      };
      for (const [k, v] of Object.entries(aliases)) {
        if (!existsSync(v)) {
          const pkgDir = k === "@sinclair/typebox" ? nested("typebox") : k === "@mariozechner/pi-coding-agent" ? PI : nested(k.replace("@mariozechner", "@earendil-works"));
          const pkg = JSON.parse(readFileSync(join(pkgDir, "package.json"), "utf8"));
          const entry = typeof pkg.exports === "object" ? pkg.exports["."]?.import ?? pkg.exports["."]?.default ?? pkg.exports["."] : pkg.module ?? pkg.main;
          aliases[k] = join(pkgDir, typeof entry === "object" ? entry.default : entry);
        }
      }
      const hooks = join(tmp, "alias-hooks.mjs");
      writeFileSync(
        hooks,
        `import { pathToFileURL } from "node:url";\nconst A = ${JSON.stringify(aliases)};\n` +
          `export async function resolve(spec, ctx, next) { if (A[spec]) return { url: pathToFileURL(A[spec]).href, shortCircuit: true }; return next(spec, ctx); }\n`,
      );
      const register = join(tmp, "register.mjs");
      writeFileSync(register, `import { register } from "node:module";\nregister(${JSON.stringify(`file://${hooks}`)});\n`);
      // The package maps web_search/web_fetch to files under the Pi config
      // directory; give the run the same layout the sandbox entry creates.
      const agentDir = join(tmp, "pi-agent");
      for (const tool of ["web-search", "web-fetch"]) {
        mkdirSync(join(agentDir, "extensions", tool), { recursive: true });
        writeFileSync(join(agentDir, "extensions", tool, "index.ts"), "export default function () {}\n");
      }
      const env: Record<string, string | undefined> = { ...process.env, HOME: tmp, PI_CODING_AGENT_DIR: agentDir, TMUX: "", TMUX_PANE: "" };
      delete env.NODE_TEST_CONTEXT; // otherwise the nested runner reports in child mode
      const r = spawnSync(process.execPath, ["--import", register, "--test", "--test-reporter=tap", "test/test.ts"], {
        cwd: copy,
        encoding: "utf8",
        env,
        timeout: 240_000,
      });
      const tail = `${r.stdout}\n${r.stderr}`.split("\n").slice(-40).join("\n");
      assert.equal(r.status, 0, `upstream unit tests failed (a broken upstream test is never treated as passing):\n${tail}`);
      assert.match(r.stdout, /# fail 0/);
    } finally {
      rmSync(tmp, { recursive: true, force: true });
    }
  });
});
