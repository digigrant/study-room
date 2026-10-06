"""Shared fakes for the hermetic host tests: temporary XDG homes, fake commands, fixtures."""

from __future__ import annotations

import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from studyroom import config as configmod
from studyroom import redact
from studyroom.paths import HostPaths, host_paths, repo_root
from studyroom.runner import FakeRunner, Result

FIXTURES = repo_root() / "tests" / "fixtures"

# Obviously fake credential values. They match real token shapes so redaction
# is exercised, and say FAKE so the repository secret scan can tell them apart.
FAKE_ACCESS = "eyJhbGciOiJub25lIn0.eyJGQUtFIjoiYWNjZXNzIn0.FAKEsignatureFAKE"
FAKE_REFRESH = "rt_FAKE_refresh_token_0123456789abcdef"
FAKE_PAT = "ghp_FAKE0000000000000000000000000000000000"
FAKE_CLIENT_SECRET = "FAKE-client-secret-0123456789"


def host_fixture(name: str) -> dict:
    return json.loads((FIXTURES / "hosts" / f"{name}.json").read_text())


class TempHome(unittest.TestCase):
    """A test case with an isolated HOME and XDG directories."""

    def setUp(self) -> None:
        super().setUp()
        self.tmp = Path(tempfile.mkdtemp(prefix="sr-host-"))
        self.home = self.tmp / "home"
        self.home.mkdir()
        self.env = {"HOME": str(self.home)}
        self.paths: HostPaths = host_paths(self.env)
        redact.REGISTRY.clear()

    def tearDown(self) -> None:
        shutil.rmtree(self.tmp, ignore_errors=True)
        redact.REGISTRY.clear()
        super().tearDown()

    def make_config(self, **overrides) -> configmod.Config:
        cfg = configmod.load(self.paths, create=True)
        cfg.data["installation_id"] = "3f1c2b9e-7a64-4d2e-9b1f-0c5d8e2a4f61"
        cfg.data["profiles"]["main"]["model"] = "gpt-teach"
        for dotted, value in overrides.items():
            node = cfg.data
            parts = dotted.split(".")
            for part in parts[:-1]:
                node = node[part]
            node[parts[-1]] = value
        cfg.save()
        return cfg

    def make_vault(self, cfg: configmod.Config, *, opened: bool = True, study: bool = True) -> None:
        cfg.vault_path.mkdir(parents=True, exist_ok=True)
        if opened:
            (cfg.vault_path / ".obsidian").mkdir(exist_ok=True)
            (cfg.vault_path / ".obsidian" / "core-plugins.json").write_text(json.dumps(["file-explorer", "sync"]))
        if study:
            cfg.study_dir.mkdir(exist_ok=True)


def git_runner() -> FakeRunner:
    """A runner whose git says 'not a work tree' and pgrep finds nothing."""
    r = FakeRunner()
    r.on(["git"], Result([], 128, "", "fatal: not a git repository"))
    r.on(["pgrep"], Result([], 1, "", ""))
    return r


def env_without(*names: str) -> dict[str, str]:
    return {k: v for k, v in os.environ.items() if k not in names}
