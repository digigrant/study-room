#!/usr/bin/env node
// Deterministic digest of a directory tree: sorted relative paths, entry type,
// executable bit, and SHA-256 of contents (symlink targets for links).
// Used to pin the installed npm tree, because npm does not enforce lockfile
// integrity inside a dependency's own npm-shrinkwrap.json (Pi ships one whose
// @earendil-works entries carry no integrity). Usage:
//   tree-digest.mjs <dir> [--exclude <relative path>]...
import { createHash } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, readlinkSync } from "node:fs";
import { join, relative, sep } from "node:path";

export function treeDigest(root, exclude = []) {
  const skip = new Set(exclude);
  const entries = [];
  const walk = (dir) => {
    for (const name of readdirSync(dir).sort()) {
      const abs = join(dir, name);
      const rel = relative(root, abs).split(sep).join("/");
      if (skip.has(rel)) continue;
      const st = lstatSync(abs);
      if (st.isSymbolicLink()) {
        entries.push(`l ${rel} ${readlinkSync(abs)}`);
      } else if (st.isDirectory()) {
        entries.push(`d ${rel}`);
        walk(abs);
      } else if (st.isFile()) {
        const exec = st.mode & 0o111 ? "x" : "-";
        const sum = createHash("sha256").update(readFileSync(abs)).digest("hex");
        entries.push(`f ${rel} ${exec} ${sum}`);
      }
    }
  };
  walk(root);
  return { digest: createHash("sha256").update(entries.join("\n") + "\n").digest("hex"), count: entries.length };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const args = process.argv.slice(2);
  const root = args.shift();
  const exclude = [];
  while (args.length) {
    const flag = args.shift();
    if (flag !== "--exclude" || !args.length) {
      console.error("usage: tree-digest.mjs <dir> [--exclude <relative path>]...");
      process.exit(2);
    }
    exclude.push(args.shift());
  }
  if (!root) {
    console.error("usage: tree-digest.mjs <dir> [--exclude <relative path>]...");
    process.exit(2);
  }
  const { digest, count } = treeDigest(root, exclude);
  console.log(`${digest} ${count}`);
}
