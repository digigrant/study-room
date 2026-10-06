"""`study-room test`: the hermetic suites (SPEC 20.1).

Runs without real credentials, provider requests, GitHub mutations or the
real vault:

1. host suite: Python unit tests with fake commands, fake HTTP, fake keyring
   and fake Infisical (tests/host);
2. sandbox suite: the TypeScript suites inside the built sandbox image with
   networking disabled (`docker run --network none`), including the tmux
   researcher lifecycle against a scripted local provider.

A suite that cannot run here is reported as SKIPPED with its reason, never as
passed.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from dataclasses import dataclass

from . import image
from .lock import load
from .paths import repo_root
from .runner import Runner


@dataclass
class SuiteResult:
    name: str
    status: str  # passed | failed | skipped
    detail: str


def host_suite(verbosity: int = 1) -> SuiteResult:
    loader = unittest.TestLoader()
    suite = loader.discover(str(repo_root() / "tests" / "host"), top_level_dir=str(repo_root()))
    result = unittest.TextTestRunner(verbosity=verbosity, stream=sys.stderr).run(suite)
    skipped = len(result.skipped)
    detail = f"{result.testsRun} tests, {len(result.failures)} failures, {len(result.errors)} errors, {skipped} skipped"
    if skipped:
        detail += " (" + "; ".join(sorted({reason for _, reason in result.skipped})) + ")"
    return SuiteResult("host", "passed" if result.wasSuccessful() else "failed", detail)


def sandbox_suite(runner: Runner, *, build: bool = False, integration: bool = True) -> SuiteResult:
    if runner.which("docker") is None:
        return SuiteResult("sandbox", "skipped", "Docker is not installed, so the sandbox image cannot run here")
    if not image.docker_usable(runner):
        return SuiteResult("sandbox", "skipped", "this user cannot reach the Docker daemon")
    lock = load()
    tag = image.image_tag(lock)
    have = runner.run(["docker", "image", "inspect", tag], timeout=60).ok
    if not have:
        if not build:
            return SuiteResult("sandbox", "skipped", f"image {tag} is not built; run `study-room test --build` or `study-room build`")
        image.build(runner, lock, tag)
    argv = ["docker", "run", "--rm", "--network", "none", tag, "/opt/study-room/bin/study-room-selftest"]
    if integration:
        argv.append("--integration")
    code = subprocess.call(argv)
    return SuiteResult("sandbox", "passed" if code == 0 else "failed", f"{tag}, network disabled, exit {code}")


def run(runner: Runner, *, build: bool = False, only: str | None = None, verbosity: int = 1) -> int:
    results: list[SuiteResult] = []
    if only in (None, "host"):
        results.append(host_suite(verbosity))
    if only in (None, "sandbox"):
        results.append(sandbox_suite(runner, build=build))
    print("\nStudy Room hermetic tests:")
    for r in results:
        print(f"  {r.status.upper():<8} {r.name}: {r.detail}")
    if any(r.status == "failed" for r in results):
        return 1
    return 0
