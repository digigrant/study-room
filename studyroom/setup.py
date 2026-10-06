"""`study-room setup`: detect, show, ask, apply (SPEC 16.1).

Setup never changes the host without showing the exact change first and
receiving approval. ``--yes`` approves the proposed host changes; it never
skips an interactive authentication ceremony (Docker login, Infisical
handles, Obsidian Sync, provider sign-in). A pin that cannot be satisfied
stops setup: no unreviewed latest version is installed in its place.
"""

from __future__ import annotations

import shlex
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import lock as lockmod
from .errors import Failure, fail
from .hostdetect import MIN_FREE_GIB, SUPPORTED_UBUNTU, HostFacts
from .paths import HostPaths
from .runner import Runner

CATEGORIES = {
    "package": "install system packages (sudo)",
    "repository": "add a package repository (sudo)",
    "group": "change group membership (sudo)",
    "policy": "initialize Docker Sandboxes' global network policy",
    "install": "install a downloaded, checksum-verified package (sudo)",
}


@dataclass
class Change:
    key: str
    category: str
    title: str
    reason: str
    commands: list[list[str]]
    after: str | None = None  # what the user must do for the change to take effect
    optional: bool = False
    prepare: Callable[[], None] | None = None  # non-sudo preparation (download + verify)

    def render(self) -> list[str]:
        lines = [f"[{self.key}] {self.title}{' (optional)' if self.optional else ''}", f"    why: {self.reason}"]
        for argv in self.commands:
            lines.append(f"    $ {shlex.join(argv)}")
        if self.after:
            lines.append(f"    afterwards: {self.after}")
        return lines


@dataclass
class Blocker:
    failure: Failure
    message: str
    hint: str


@dataclass
class Plan:
    blockers: list[Blocker] = field(default_factory=list)
    changes: list[Change] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def empty(self) -> bool:
        return not self.changes and not self.blockers


def _apt_missing(facts_installed: dict[str, str | None], names: list[str]) -> list[str]:
    return [n for n in names if not facts_installed.get(n)]


def docker_repo_commands(lock: lockmod.Lock, key_file: Path) -> list[list[str]]:
    repo = lock["docker_apt_repository"]
    line = f"deb [arch={repo['architecture']} signed-by=/etc/apt/keyrings/docker.asc] {repo['url']} {repo['suite']} {repo['component']}"
    return [
        ["sudo", "install", "-m", "0755", "-d", "/etc/apt/keyrings"],
        ["sudo", "install", "-m", "0644", str(key_file), "/etc/apt/keyrings/docker.asc"],
        ["sudo", "sh", "-c", f"printf '%s\\n' {shlex.quote(line)} > /etc/apt/sources.list.d/docker.list"],
        ["sudo", "apt-get", "update"],
    ]


def build_plan(
    facts: HostFacts,
    lock: lockmod.Lock,
    paths: HostPaths,
    installed: dict[str, str | None],
    *,
    sbx_apt_version: str | None,
    docker_repo_configured: bool,
    prepare_obsidian: Callable[[], None] | None = None,
    prepare_docker_key: Callable[[], None] | None = None,
) -> Plan:
    plan = Plan()
    # ── Platform boundary (SPEC 5) ─────────────────────────────────────────
    if facts.machine not in ("x86_64", "amd64"):
        plan.blockers.append(Blocker(Failure.UNSUPPORTED_PLATFORM, f"architecture {facts.machine} is not supported", "Study Room V1 supports x86_64 hosts only"))
    if facts.os_id != "ubuntu" or facts.os_version != SUPPORTED_UBUNTU:
        plan.blockers.append(
            Blocker(Failure.UNSUPPORTED_PLATFORM, f"{facts.os_pretty or facts.os_id} is not supported", f"use Ubuntu {SUPPORTED_UBUNTU} (native Desktop or WSL2)")
        )
    if facts.display_kind is None:
        plan.blockers.append(
            Blocker(
                Failure.UNSUPPORTED_PLATFORM,
                "no graphical session (Wayland, X11 or WSLg) is available",
                "headless hosts are not supported: Obsidian Desktop needs a desktop session (on WSL2 enable WSLg)",
            )
        )
    if not facts.systemd_system:
        hint = "on WSL2 set [boot] systemd=true in /etc/wsl.conf, then run `wsl --shutdown` from Windows" if facts.wsl2 else "boot with systemd"
        plan.blockers.append(Blocker(Failure.MISSING_PREREQUISITE, "systemd is not running", hint))
    elif not facts.systemd_user:
        plan.blockers.append(Blocker(Failure.MISSING_PREREQUISITE, "no systemd user session", "log in through a normal session so a user manager and D-Bus session bus run"))
    if not facts.kvm_device:
        hint = "enable nested virtualization for WSL2 (Windows: WSL settings, then `wsl --shutdown`)" if facts.wsl2 else "enable virtualization (VT-x/AMD-V) in the firmware"
        plan.blockers.append(Blocker(Failure.MISSING_PREREQUISITE, "/dev/kvm is not available", hint))
    if not facts.sudo_available:
        plan.blockers.append(Blocker(Failure.MISSING_PREREQUISITE, "sudo is not available", "Study Room needs sudo for approved host changes"))
    if facts.disk_free_gib < MIN_FREE_GIB:
        plan.blockers.append(Blocker(Failure.MISSING_PREREQUISITE, f"only {facts.disk_free_gib:.1f} GiB free in $HOME", f"free at least {MIN_FREE_GIB} GiB for images and the vault replica"))

    # ── Packages from the Ubuntu archive ──────────────────────────────────
    ubuntu_pkgs = [p["name"] for p in lock["system_packages"]["host"] if p["source"] == "ubuntu"]
    missing = _apt_missing(installed, ubuntu_pkgs)
    if missing:
        plan.changes.append(
            Change(
                "packages",
                "package",
                f"Install {', '.join(missing)}",
                "keyring access (secret-tool, gnome-keyring, D-Bus user session), browser/URI opening, and key verification",
                [["sudo", "apt-get", "update"], ["sudo", "apt-get", "install", "-y", "--no-install-recommends", *missing]],
                after="log out and back in if gnome-keyring or dbus-user-session was newly installed",
            )
        )

    # ── Docker Engine and Docker Sandboxes from Docker's repository ──────
    sbx_pin = lock["docker_sandboxes"]["version"]
    docker_pkgs = [p["name"] for p in lock["system_packages"]["host"] if p["source"] == "docker" and p["name"] != "docker-sbx"]
    need_docker = _apt_missing(installed, docker_pkgs)
    sbx_installed = installed.get("docker-sbx")
    sbx_ok = bool(sbx_installed and (sbx_installed == sbx_pin or sbx_installed.startswith(f"{sbx_pin}-") or sbx_installed.startswith(f"{sbx_pin}~")))
    if (need_docker or not sbx_ok) and not docker_repo_configured:
        key_file = paths.downloads_dir / "docker.asc"
        plan.changes.append(
            Change(
                "docker-repo",
                "repository",
                "Add Docker's apt repository (key fingerprint verified against the lock)",
                "Docker Engine builds the sandbox image; Docker Sandboxes (docker-sbx) runs it",
                docker_repo_commands(lock, key_file),
                prepare=prepare_docker_key,
            )
        )
    if need_docker or not sbx_ok:
        if docker_repo_configured and sbx_apt_version is None and not sbx_ok:
            plan.blockers.append(
                Blocker(Failure.PIN_MISMATCH, f"docker-sbx {sbx_pin} is not available from the configured repository", "Study Room never installs a different version in its place")
            )
        else:
            sbx_spec = f"docker-sbx={sbx_apt_version}" if sbx_apt_version else f"docker-sbx={sbx_pin}*"
            pkgs = need_docker + ([] if sbx_ok else [sbx_spec])
            plan.changes.append(
                Change(
                    "docker",
                    "package",
                    f"Install {', '.join(pkgs)}" + (f" (replacing docker-sbx {sbx_installed})" if sbx_installed and not sbx_ok else ""),
                    f"pinned Docker Sandboxes {sbx_pin} and the Docker Engine that builds the image",
                    [["sudo", "apt-get", "install", "-y", "--allow-downgrades", *pkgs]],
                )
            )

    # ── Groups ─────────────────────────────────────────────────────────────
    if facts.kvm_device and not facts.kvm_accessible and "kvm" not in facts.configured_groups:
        plan.changes.append(
            Change("kvm-group", "group", f"Add {facts.user} to the kvm group", "Docker Sandboxes runs each sandbox as a KVM microVM", [["sudo", "usermod", "-aG", "kvm", facts.user]], after="log out and back in (or run `newgrp kvm`)")
        )
    elif facts.kvm_device and not facts.kvm_accessible:
        plan.notes.append("you are in the kvm group but this session predates it: log out and back in")
    if "docker" not in facts.configured_groups:
        plan.changes.append(
            Change(
                "docker-group",
                "group",
                f"Add {facts.user} to the docker group",
                "lets `study-room build` use Docker without sudo. Membership is equivalent to root on this host; decline to build with sudo instead",
                [["sudo", "usermod", "-aG", "docker", facts.user]],
                after="log out and back in",
                optional=True,
            )
        )

    # ── Docker Sandboxes policy (global, one-time, only if uninitialized) ──
    if facts.sbx_cli and facts.sbx_policy_initialized is False:
        plan.changes.append(
            Change(
                "sbx-policy",
                "policy",
                "Initialize Docker Sandboxes' network policy with the balanced preset",
                "sandboxes need an initialized policy; Study Room then adds only sandbox-scoped rules. An existing policy is never overwritten",
                [["sbx", "policy", "init", "balanced"]],
            )
        )

    # ── Obsidian Desktop ───────────────────────────────────────────────────
    obs = lock["obsidian_desktop"]
    if facts.obsidian_installed_version != obs["version"]:
        from .obsidian import deb_path, install_argv

        deb = deb_path(paths, obs)
        verb = f"Replace Obsidian {facts.obsidian_installed_version} with" if facts.obsidian_installed_version else "Install"
        plan.changes.append(
            Change(
                "obsidian",
                "install",
                f"{verb} Obsidian Desktop {obs['version']} (.deb, sha256 {obs['sha256'][:16]}…)",
                "the graphical Obsidian client that owns the vault replica and Sync",
                [install_argv(deb)],
                prepare=prepare_obsidian,
            )
        )
    return plan


def render(plan: Plan) -> list[str]:
    lines: list[str] = []
    for b in plan.blockers:
        lines.append(f"BLOCKED ({b.failure.value}): {b.message}\n    {b.hint}")
    if plan.changes:
        lines.append("Proposed host changes (nothing has been changed yet):")
        for c in plan.changes:
            lines += c.render()
    for note in plan.notes:
        lines.append(f"note: {note}")
    if plan.empty and not plan.notes:
        lines.append("No host changes are needed.")
    return lines


Approver = Callable[[Change], bool]


def apply(plan: Plan, runner: Runner, approve: Approver, *, say=print) -> list[str]:
    """Run only approved changes. Returns the after-instructions that apply."""
    if plan.blockers:
        b = plan.blockers[0]
        raise fail(b.failure, b.message, hint=b.hint)
    afters: list[str] = []
    for change in plan.changes:
        if not approve(change):
            if change.optional:
                say(f"skipped (declined): {change.title}")
                continue
            raise fail(Failure.PERMISSION_DECLINED, f"declined: {change.title}", hint="nothing after this step was changed; rerun `study-room setup` when ready")
        if change.prepare:
            change.prepare()
        for argv in change.commands:
            say(f"$ {shlex.join(argv)}")
            code = runner.interactive(argv)
            if code != 0:
                raise fail(Failure.MISSING_PREREQUISITE, f"`{shlex.join(argv)}` failed (exit {code})", hint="fix the error above and rerun `study-room setup`; completed steps are not repeated")
        if change.after:
            afters.append(f"{change.title}: {change.after}")
    return afters


def installed_packages(runner: Runner, names: list[str]) -> dict[str, str | None]:
    out: dict[str, str | None] = {}
    for name in names:
        res = runner.run(["dpkg-query", "-W", "-f=${Status}|${Version}", name], timeout=20)
        if res.ok and res.stdout.startswith("install ok installed|"):
            out[name] = res.stdout.split("|", 1)[1].strip()
        else:
            out[name] = None
    return out


def sbx_candidate_version(runner: Runner, pin: str) -> str | None:
    """The apt version string of docker-sbx matching the pin exactly, if the repository offers it."""
    res = runner.run(["apt-cache", "madison", "docker-sbx"], timeout=60)
    if not res.ok:
        return None
    for line in res.stdout.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 2:
            version = parts[1]
            if version == pin or version.startswith(f"{pin}-") or version.startswith(f"{pin}~"):
                return version
    return None


def docker_repo_configured() -> bool:
    return Path("/etc/apt/sources.list.d/docker.list").exists() or Path("/etc/apt/sources.list.d/docker.sources").exists()


def verify_key_fingerprint(runner: Runner, key_file: Path, expected: str) -> None:
    res = runner.run(["gpg", "--show-keys", "--with-colons", "--fingerprint", str(key_file)], timeout=30)
    fprs = [line.split(":")[9] for line in res.stdout.splitlines() if line.startswith("fpr:")]
    if expected.upper() not in [f.upper() for f in fprs]:
        raise fail(Failure.PIN_MISMATCH, "Docker's repository key does not have the pinned fingerprint", hint=f"expected {expected}; the key was not installed")
