"""Build the sandbox image from the lock and load it into Docker Sandboxes.

The image is built locally with Docker (the build arguments carry every pin
from the lock manifest), saved, and loaded as a Docker Sandboxes template.
It is never pushed anywhere (SPEC 4). The tag combines the lock fingerprint
with a digest of the sandbox sources, so any pin or code change produces a
new template and an unchanged checkout reuses the existing one.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from . import lock as lockmod
from .errors import Failure, fail
from .paths import HostPaths, repo_root
from .runner import Runner
from .sbx import Sbx

EXCLUDE_DIRS = {"node_modules", "__pycache__"}


def source_digest(root: Path | None = None) -> str:
    root = root or repo_root()
    digest = hashlib.sha256()
    files = [root / "sandbox" / "Dockerfile", root / ".dockerignore"]
    for dirpath, dirnames, filenames in os.walk(root / "sandbox"):
        dirnames[:] = sorted(d for d in dirnames if d not in EXCLUDE_DIRS and not os.path.islink(os.path.join(dirpath, d)))
        for name in sorted(filenames):
            files.append(Path(dirpath) / name)
    for path in sorted(set(files)):
        if path.is_symlink() or not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        digest.update(rel.encode() + b"\0")
        digest.update(b"x" if os.access(path, os.X_OK) else b"-")
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()


def image_tag(lock: lockmod.Lock, root: Path | None = None) -> str:
    repo = lock["sandbox_image"]["repository"]
    return f"{repo}:{lock.fingerprint[:12]}-{source_digest(root)[:12]}"


def build_command(lock: lockmod.Lock, tag: str, *, root: Path | None = None, no_cache: bool = False, sudo: bool = False) -> list[str]:
    root = root or repo_root()
    argv = (["sudo"] if sudo else []) + [
        "docker", "build",
        "--platform", lock["sandbox_image"]["base"]["platform"],
        "-f", str(root / "sandbox" / "Dockerfile"),
        "-t", tag,
    ]
    if no_cache:
        argv += ["--no-cache", "--pull"]
    for key, value in lockmod.build_args(lock.data).items():
        argv += ["--build-arg", f"{key}={value}"]
    argv.append(str(root))
    return argv


def docker_usable(runner: Runner) -> bool:
    return runner.run(["docker", "info", "--format", "{{.ServerVersion}}"], timeout=30).ok


def build(runner: Runner, lock: lockmod.Lock, tag: str, *, no_cache: bool = False, allow_sudo: bool = False, say=print) -> None:
    lockmod.require_valid(lock)
    if runner.which("docker") is None:
        raise fail(Failure.MISSING_PREREQUISITE, "Docker is not installed", hint="run `study-room setup`")
    sudo = False
    if not docker_usable(runner):
        if not allow_sudo:
            raise fail(
                Failure.PERMISSION_DECLINED,
                "this user cannot reach the Docker daemon",
                hint="accept the docker group change in `study-room setup`, or rerun with --sudo-docker to build with sudo",
            )
        sudo = True
    say(f"Building the sandbox image {tag} from the lock manifest{' (no cache)' if no_cache else ''}...")
    code = runner.interactive(build_command(lock, tag, no_cache=no_cache, sudo=sudo))
    if code != 0:
        raise fail(Failure.PIN_MISMATCH, f"the sandbox image build failed (exit {code})", hint="a pin, checksum or digest mismatch stops the build; see the output above")


def load_template(runner: Runner, sbx: Sbx, tag: str, paths: HostPaths, *, sudo: bool = False) -> None:
    paths.cache_dir.mkdir(parents=True, exist_ok=True)
    tar = paths.cache_dir / f"sandbox-{tag.split(':')[-1]}.tar"
    res = runner.run((["sudo"] if sudo else []) + ["docker", "image", "save", tag, "-o", str(tar)], timeout=1800)
    if not res.ok:
        raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, f"docker image save failed: {res.stderr.strip()[:200]}")
    try:
        sbx.template_load(str(tar))
    finally:
        try:
            tar.unlink()
        except FileNotFoundError:
            pass


def ensure(runner: Runner, sbx: Sbx, lock: lockmod.Lock, paths: HostPaths, *, rebuild: bool = False, allow_sudo: bool = False, say=print) -> str:
    """Return the template tag for this checkout, building and loading it if needed."""
    tag = image_tag(lock)
    if not rebuild and sbx.has_template(tag):
        return tag
    build(runner, lock, tag, no_cache=rebuild, allow_sudo=allow_sudo, say=say)
    load_template(runner, sbx, tag, paths, sudo=not docker_usable(runner))
    return tag
