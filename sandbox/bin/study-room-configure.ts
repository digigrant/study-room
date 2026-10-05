// Root-only configuration step, run by the trusted host as
//   sbx exec -i -u root <sandbox> /opt/study-room/bin/study-room-configure
// with the profile JSON on stdin. It writes root-owned, agent-readable files
// the agent cannot change without sudo: the profile, the trusted researcher
// definition, and the /workspace link to the mounted Study Room/ directory.

import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, renameSync, statSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { renderResearcherDefinition } from "../lib/policy.ts";
import { ROOT, layout, piModel, validateProfile } from "../lib/profile.ts";

function writeRootFile(path: string, content: string): void {
  mkdirSync(dirname(path), { recursive: true, mode: 0o755 });
  const tmp = `${path}.tmp-${process.pid}`;
  writeFileSync(tmp, content, { mode: 0o644 });
  chmodSync(tmp, 0o644);
  renameSync(tmp, path);
}

export function configure(rawProfile: string, root = ROOT, workspaceLink = "/workspace"): string[] {
  const profile = validateProfile(JSON.parse(rawProfile));
  const notes: string[] = [];
  writeRootFile(join(root, "etc", "profile.json"), JSON.stringify(profile, null, 2) + "\n");
  const researcherModel = piModel(profile.researcher);
  if (researcherModel) {
    writeRootFile(join(root, "etc", "agents", "researcher.md"), renderResearcherDefinition({ model: researcherModel, thinking: profile.researcher.thinking }));
  } else {
    notes.push("researcher model not configured: subagents stay disabled");
  }
  if (!existsSync(profile.workspace) || !statSync(profile.workspace).isDirectory()) {
    throw new Error(`the Study Room workspace is not mounted at ${profile.workspace}`);
  }
  let replace = true;
  try {
    const st = lstatSync(workspaceLink);
    if (!st.isSymbolicLink()) throw new Error(`${workspaceLink} exists and is not a symlink; refusing to replace it`);
  } catch (err: any) {
    if (err?.code !== "ENOENT") throw err;
    replace = false;
  }
  if (replace) unlinkSync(workspaceLink);
  symlinkSync(profile.workspace, workspaceLink);
  notes.push(`${workspaceLink} -> ${profile.workspace}`);
  return notes;
}

if (import.meta.url === `file://${process.argv[1]}`) {
  if (process.getuid && process.getuid() !== 0) {
    console.error("study-room-configure must run as root (sbx exec -u root)");
    process.exit(2);
  }
  try {
    const notes = configure(readFileSync(0, "utf8"));
    for (const n of notes) console.log(`study-room-configure: ${n}`);
  } catch (err: any) {
    console.error(`study-room-configure: ${err?.message ?? err}`);
    process.exit(1);
  }
}
