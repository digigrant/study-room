"""Lock manifest validation (SPEC 17, 20.1: lock/checksum validation)."""

from __future__ import annotations

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from studyroom import image
from studyroom import lock as lockmod
from studyroom.errors import StudyRoomError
from studyroom.paths import repo_root


class LockTests(unittest.TestCase):
    def setUp(self) -> None:
        self.lock = lockmod.load()

    def test_checked_in_lock_is_consistent(self) -> None:
        self.assertEqual(lockmod.validate(self.lock), [])

    def test_initial_pins_match_the_specification(self) -> None:
        d = self.lock.data
        self.assertEqual(d["docker_sandboxes"]["version"], "0.46.0")
        self.assertEqual(d["npm"]["packages"]["@earendil-works/pi-coding-agent"]["version"], "1.0.0")
        self.assertEqual(d["npm"]["packages"]["pi-web-search"]["version"], "1.6.0")
        self.assertEqual(d["npm"]["packages"]["pi-web-search"]["inspected_commit"], "66e14d30be2fc4b56ef4a0f77efd55cd81f1b5c4")
        self.assertEqual(d["git_sources"]["learn"]["commit"], "7cfd8942f82ab9476e63572387e1fe9bcea5082c")
        self.assertEqual(d["git_sources"]["pi-interactive-subagents"]["commit"], "c3e8b53c0754ae5ccc19fdab5a7481ec039bc2f7")
        self.assertFalse(d["sandbox_image"]["publish"])

    def _with(self, mutate) -> list[str]:
        tmp = Path(tempfile.mkdtemp(prefix="sr-lock-"))
        try:
            root = repo_root()
            (tmp / "lock").mkdir()
            shutil.copytree(root / "sandbox" / "runtime", tmp / "sandbox" / "runtime")
            shutil.copy(root / "sandbox" / "Dockerfile", tmp / "sandbox" / "Dockerfile")
            data = copy.deepcopy(self.lock.data)
            mutate(data, tmp)
            (tmp / "lock" / "study-room.lock.json").write_text(json.dumps(data))
            return lockmod.validate(lockmod.load(tmp), tmp)
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_detects_tampering(self) -> None:
        def integrity(d, _):
            d["npm"]["packages"]["pi-web-search"]["integrity"] = "sha512-" + "A" * 86 + "=="

        def lockfile(_, root):
            p = root / "sandbox" / "runtime" / "package-lock.json"
            p.write_text(p.read_text().replace('"version": "1.6.0"', '"version": "1.6.1"', 1))

        def learn_extra(d, _):
            d["git_sources"]["learn"]["load"].append("skills/visualize")

        def publish(d, _):
            d["sandbox_image"]["publish"] = True

        def short_commit(d, _):
            d["git_sources"]["learn"]["commit"] = "7cfd894"

        def docker_default(_, root):
            p = root / "sandbox" / "Dockerfile"
            p.write_text(p.read_text().replace("ARG NODE_VERSION\n", "ARG NODE_VERSION=latest\n"))

        def missing_integrity(_, root):
            p = root / "sandbox" / "runtime" / "package-lock.json"
            data = json.loads(p.read_text())
            key = next(k for k in data["packages"] if k)
            del data["packages"][key]["integrity"]
            p.write_text(json.dumps(data))

        def latest_obsidian(d, _):
            d["obsidian_desktop"]["url"] = "https://github.com/obsidianmd/obsidian-releases/releases/latest"

        def expensive_live(d, _):
            d["verification"]["openai"]["limits"]["max_output_tokens"] = 100000

        def patch(d, _):
            d["patches"] = [{"file": "x.patch"}]

        for name, mutate, needle in [
            ("integrity", integrity, "integrity"),
            ("lockfile", lockfile, "sha256"),
            ("learn resources", learn_extra, "approved resources"),
            ("publish", publish, "publish"),
            ("short commit", short_commit, "commit"),
            ("dockerfile default", docker_default, "defaults"),
            ("missing integrity", missing_integrity, "no sha512 integrity"),
            ("unpinned obsidian", latest_obsidian, "obsidian_desktop.url"),
            ("live limits", expensive_live, "max_output_tokens"),
            ("patches", patch, "patches"),
        ]:
            problems = self._with(mutate)
            self.assertTrue(any(needle in p for p in problems), f"{name}: {problems}")

    def test_require_valid_raises_pin_mismatch(self) -> None:
        bad = lockmod.Lock(copy.deepcopy(self.lock.data), self.lock.path)
        bad.data["node"]["sha256"] = "zz"
        with self.assertRaises(StudyRoomError) as ctx:
            lockmod.require_valid(bad, repo_root())
        self.assertEqual(ctx.exception.failure.value, "pin/checksum mismatch")

    def test_build_arguments_carry_every_pin(self) -> None:
        args = lockmod.build_args(self.lock.data)
        self.assertTrue(args["BASE_IMAGE"].startswith("docker/sandbox-templates:shell-"))
        self.assertIn("@sha256:", args["BASE_IMAGE"])
        self.assertEqual(args["LEARN_TREE"], self.lock.git_source("learn")["tree"])
        self.assertEqual(args["NPM_TREE_SHA256"], self.lock["npm"]["installed_tree_sha256"])
        argv = image.build_command(self.lock, "study-room/sandbox:test")
        for key, value in args.items():
            self.assertIn(f"{key}={value}", argv)
        self.assertNotIn("latest", " ".join(argv))

    def test_image_tag_tracks_pins_and_sources(self) -> None:
        tag = image.image_tag(self.lock)
        self.assertTrue(tag.startswith("study-room/sandbox:"))
        self.assertEqual(tag, image.image_tag(self.lock), "stable for an unchanged checkout")
        changed = lockmod.Lock(copy.deepcopy(self.lock.data), self.lock.path)
        changed.data["node"]["version"] = "22.99.0"
        self.assertNotEqual(image.image_tag(changed), tag)

    def test_fingerprint_is_stable_and_order_independent(self) -> None:
        a = lockmod.Lock(json.loads(json.dumps(self.lock.data)), self.lock.path)
        b = lockmod.Lock(dict(reversed(list(self.lock.data.items()))), self.lock.path)
        self.assertEqual(a.fingerprint, b.fingerprint)


if __name__ == "__main__":
    unittest.main()
