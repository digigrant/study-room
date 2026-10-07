// In-sandbox diagnostics, run by `study-room doctor` on the host as
//   sbx exec <sandbox> /opt/study-room/bin/study-room-diagnose --json
// Reports pinned versions, upstream checkout integrity, the installed npm
// tree digest, the configured profile, requested/effective thinking levels,
// and the workspace mount boundary. Prints no secret: the only credentials in
// the sandbox are proxy placeholders, and they are not read here.

import { execFileSync } from "node:child_process";
import { existsSync, readFileSync, readlinkSync, realpathSync } from "node:fs";
import { dirname, join } from "node:path";
import { treeDigest } from "./tree-digest.mjs";
import { catalogModel, describe as describeThinking, report } from "../lib/thinking.ts";
import { ROOT, layout, loadProfile, piModel } from "../lib/profile.ts";

interface Check {
  name: string;
  ok: boolean;
  detail: string;
}

export async function diagnose(opts: { root?: string; skipTree?: boolean } = {}): Promise<{ ok: boolean; checks: Check[] }> {
  const root = opts.root ?? ROOT;
  const checks: Check[] = [];
  const add = (name: string, ok: boolean, detail: string) => checks.push({ name, ok, detail });
  let build: any = null;
  try {
    build = JSON.parse(readFileSync(join(root, "etc", "build.json"), "utf8"));
    add("build manifest", true, `node ${build.node}`);
  } catch {
    add("build manifest", false, `${join(root, "etc", "build.json")} missing: not a Study Room image`);
  }
  const nodeVersion = process.version.replace(/^v/, "");
  add("node", !build || build.node === nodeVersion, `running ${nodeVersion}${build ? `, pinned ${build.node}` : ""}`);
  try {
    const pkg = JSON.parse(readFileSync(join(root, "runtime", "node_modules", "@earendil-works", "pi-coding-agent", "package.json"), "utf8"));
    add("pi", true, `@earendil-works/pi-coding-agent ${pkg.version}`);
  } catch {
    add("pi", false, "Pi is not installed in the runtime");
  }
  if (build) {
    for (const [name, src] of Object.entries<any>(build.upstream ?? {})) {
      try {
        const out = execFileSync(join(root, "bin", "verify-checkout.sh"), [src.dir, src.url, src.commit, src.tree], { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
        add(`upstream ${name}`, true, out.trim());
      } catch (err: any) {
        add(`upstream ${name}`, false, String(err?.stderr ?? err?.message ?? err).trim());
      }
    }
    if (!opts.skipTree) {
      const { digest } = treeDigest(join(root, "runtime", "node_modules"));
      add("npm tree", digest === build.npm_tree_sha256, digest === build.npm_tree_sha256 ? "matches the lock" : `digest ${digest} differs from the lock`);
    }
  }
  try {
    const p = loadProfile(join(root, "etc", "profile.json"));
    add("profile", true, `network ${p.network_mode}, main ${piModel(p.main) ?? "unset"}, researcher ${piModel(p.researcher) ?? "unset"}`);
    const l = layout(undefined, root);
    for (const [label, m] of [["main thinking", p.main], ["researcher thinking", p.researcher]] as const) {
      const meta = m.model ? await catalogModel(l.runtime, m.pi_provider, m.model) : null;
      const r = report(meta, piModel(m) ?? "unset", m.thinking);
      add(label, r.effective !== null, describeThinking(r));
    }
    const mounted = existsSync(p.workspace);
    add("workspace mount", mounted, mounted ? p.workspace : `${p.workspace} is not mounted`);
    let link = "";
    try {
      link = readlinkSync("/workspace");
    } catch {
      link = "";
    }
    add("/workspace link", link === p.workspace, link ? `/workspace -> ${link}` : "/workspace is missing");
    // Only Study Room/ comes from the host: the vault root and its Obsidian
    // state must not be visible next to it.
    if (mounted) {
      const parent = dirname(realpathSync(p.workspace));
      const leaked = [".obsidian", ".trash"].filter((n) => existsSync(join(parent, n)));
      add("vault boundary", leaked.length === 0, leaked.length ? `vault files visible beside the workspace: ${leaked.join(", ")}` : "only Study Room/ is mounted");
      const gitDir = [p.workspace, parent].find((d) => existsSync(join(d, ".git")));
      add("no git in vault", !gitDir, gitDir ? `${gitDir} contains a .git directory (SPEC 9.1)` : "vault paths are not Git repositories");
    }
  } catch (err: any) {
    add("profile", false, err?.message ?? String(err));
  }
  return { ok: checks.every((c) => c.ok), checks };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const json = process.argv.includes("--json");
  diagnose({ skipTree: process.argv.includes("--quick") }).then((r) => {
    if (json) console.log(JSON.stringify(r, null, 2));
    else for (const c of r.checks) console.log(`${c.ok ? "ok  " : "FAIL"} ${c.name}: ${c.detail}`);
    process.exit(r.ok ? 0 : 1);
  });
}
