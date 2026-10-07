// Runs the hermetic sandbox test suites with the pinned Node, inside the
// image (or anywhere STUDY_ROOM_ROOT points at a built layout). Uses no
// credentials, provider, GitHub or vault: providers are local fakes.
// Skipped tests are reported as skipped with their reason, never as passed.

import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import { join } from "node:path";
import { ROOT } from "../lib/profile.ts";

const dir = join(ROOT, "tests");
const files = readdirSync(dir)
  .filter((f) => f.endsWith(".test.ts"))
  .sort()
  .map((f) => join(dir, f));
const integration = process.argv.includes("--integration");
const selected = files.filter((f) => integration || !f.includes(".integration."));
const r = spawnSync(process.execPath, ["--test", "--test-concurrency=1", "--test-reporter=spec", ...selected], {
  stdio: "inherit",
  env: { ...process.env, STUDY_ROOM_ROOT: ROOT },
});
process.exit(r.status ?? 1);
