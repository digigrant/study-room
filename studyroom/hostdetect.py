"""Host capability detection (SPEC 5, 16.1 steps 1-5).

Setup detects capabilities instead of branching on a broad "is WSL" flag.
WSL2 is reported as a fact, but every decision downstream asks a capability
question: is there a graphical display, does /dev/kvm accept this user, does
a Secret Service answer, is systemd running. Native Ubuntu Desktop and WSL2
therefore share one code path, differing only where the platforms really
differ (WSLg versus a native Wayland/X11 session).

All probing goes through ``Probe`` so the hermetic tests drive detection
from JSON fixtures (tests/fixtures/hosts/).
"""

from __future__ import annotations

import grp
import json
import os
import platform
import pwd
import shutil
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .runner import Result, Runner

MIN_FREE_GIB = 15
SUPPORTED_UBUNTU = "24.04"


class Probe:
    """Reads the real host."""

    def __init__(self, runner: Runner | None = None):
        self.runner = runner or Runner()

    def read(self, path: str) -> str | None:
        try:
            return Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None

    def exists(self, path: str) -> bool:
        return os.path.exists(path)

    def access_rw(self, path: str) -> bool:
        return os.access(path, os.R_OK | os.W_OK)

    def env(self, name: str) -> str | None:
        return os.environ.get(name)

    def machine(self) -> str:
        return platform.machine()

    def user(self) -> str:
        return pwd.getpwuid(os.getuid()).pw_name

    def uid(self) -> int:
        return os.getuid()

    def groups(self) -> list[str]:
        """Groups of the *current process* (what takes effect now)."""
        return sorted({grp.getgrgid(g).gr_name for g in os.getgroups()})

    def configured_groups(self) -> list[str]:
        """Groups in /etc/group for the user (what takes effect after re-login)."""
        name = self.user()
        out = {g.gr_name for g in grp.getgrall() if name in g.gr_mem}
        try:
            out.add(grp.getgrgid(pwd.getpwnam(name).pw_gid).gr_name)
        except KeyError:
            pass
        return sorted(out)

    def disk_free_gib(self, path: str) -> float:
        target = path
        while target and not os.path.exists(target):
            target = os.path.dirname(target)
        return shutil.disk_usage(target or "/").free / (1 << 30)

    def which(self, name: str) -> str | None:
        return self.runner.which(name)

    def run(self, argv: list[str], timeout: float = 15) -> Result:
        return self.runner.run(argv, timeout=timeout)


class FixtureProbe(Probe):
    """Answers from a JSON fixture describing a host."""

    def __init__(self, fixture: dict):
        self.f = fixture

    @classmethod
    def from_file(cls, path: Path) -> "FixtureProbe":
        return cls(json.loads(path.read_text(encoding="utf-8")))

    def read(self, path):
        return self.f.get("files", {}).get(path)

    def exists(self, path):
        return path in self.f.get("files", {}) or path in self.f.get("paths", [])

    def access_rw(self, path):
        return path in self.f.get("rw_paths", [])

    def env(self, name):
        return self.f.get("env", {}).get(name)

    def machine(self):
        return self.f.get("machine", "x86_64")

    def user(self):
        return self.f.get("user", "learner")

    def uid(self):
        return int(self.f.get("uid", 1000))

    def groups(self):
        return list(self.f.get("groups", []))

    def configured_groups(self):
        return list(self.f.get("configured_groups", self.f.get("groups", [])))

    def disk_free_gib(self, path):
        return float(self.f.get("disk_free_gib", 100))

    def which(self, name):
        return f"/usr/bin/{name}" if name in self.f.get("commands", {}) or name in self.f.get("binaries", []) else None

    def run(self, argv, timeout=15):
        key = " ".join(argv)
        spec = self.f.get("commands_output", {}).get(key)
        if spec is None:
            if self.which(argv[0]) is None:
                return Result(list(argv), 127, "", f"{argv[0]}: command not found")
            return Result(list(argv), 1, "", "fixture: no output recorded")
        if isinstance(spec, str):
            return Result(list(argv), 0, spec, "")
        return Result(list(argv), int(spec.get("rc", 0)), spec.get("stdout", ""), spec.get("stderr", ""))


@dataclass
class HostFacts:
    os_id: str | None = None
    os_version: str | None = None
    os_pretty: str | None = None
    machine: str = ""
    wsl2: bool = False
    systemd_system: bool = False
    systemd_user: bool = False
    display_kind: str | None = None  # "wslg", "wayland", "x11" or None
    display_env: dict[str, str] = field(default_factory=dict)
    kvm_device: bool = False
    kvm_accessible: bool = False
    user: str = ""
    groups: list[str] = field(default_factory=list)
    configured_groups: list[str] = field(default_factory=list)
    secret_tool: bool = False
    secret_service: bool = False
    disk_free_gib: float = 0.0
    sudo_available: bool = False
    docker_cli: bool = False
    sbx_cli: bool = False
    sbx_version: str | None = None
    sbx_logged_in: bool | None = None
    sbx_policy_initialized: bool | None = None
    obsidian_installed_version: str | None = None
    git: bool = False
    python_version: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def _os_release(text: str | None) -> dict[str, str]:
    out: dict[str, str] = {}
    for line in (text or "").splitlines():
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            out[key.strip()] = value.strip().strip('"')
    return out


def _detect_display(probe: Probe, wsl2: bool) -> tuple[str | None, dict[str, str]]:
    env = {k: v for k in ("WAYLAND_DISPLAY", "DISPLAY", "XDG_SESSION_TYPE", "XDG_RUNTIME_DIR") if (v := probe.env(k))}
    has_wayland = bool(env.get("WAYLAND_DISPLAY"))
    has_x11 = bool(env.get("DISPLAY"))
    if not (has_wayland or has_x11):
        return None, env
    # WSLg exposes its sockets under /mnt/wslg; that is the capability that
    # matters, not the fact that the kernel is a WSL kernel.
    if probe.exists("/mnt/wslg") and wsl2:
        return "wslg", env
    if has_wayland:
        return "wayland", env
    return "x11", env


def detect(probe: Probe | None = None) -> HostFacts:
    probe = probe or Probe()
    facts = HostFacts()
    osr = _os_release(probe.read("/etc/os-release"))
    facts.os_id = osr.get("ID")
    facts.os_version = osr.get("VERSION_ID")
    facts.os_pretty = osr.get("PRETTY_NAME")
    facts.machine = probe.machine()

    kernel = (probe.read("/proc/sys/kernel/osrelease") or "").lower()
    facts.wsl2 = "microsoft" in kernel and ("wsl2" in kernel or probe.exists("/run/WSL"))

    facts.systemd_system = probe.exists("/run/systemd/system")
    runtime_dir = probe.env("XDG_RUNTIME_DIR") or f"/run/user/{probe.uid()}"
    facts.systemd_user = probe.exists(f"{runtime_dir}/systemd") or probe.exists(f"{runtime_dir}/bus")

    facts.display_kind, facts.display_env = _detect_display(probe, facts.wsl2)

    facts.kvm_device = probe.exists("/dev/kvm")
    facts.kvm_accessible = facts.kvm_device and probe.access_rw("/dev/kvm")

    facts.user = probe.user()
    facts.groups = probe.groups()
    facts.configured_groups = probe.configured_groups()

    facts.secret_tool = probe.which("secret-tool") is not None
    if probe.which("busctl"):
        res = probe.run(["busctl", "--user", "status", "org.freedesktop.secrets"])
        facts.secret_service = res.ok
    facts.disk_free_gib = probe.disk_free_gib(probe.env("HOME") or "/")
    facts.sudo_available = probe.which("sudo") is not None
    facts.git = probe.which("git") is not None
    facts.docker_cli = probe.which("docker") is not None

    facts.sbx_cli = probe.which("sbx") is not None
    if facts.sbx_cli:
        facts.sbx_version = _sbx_version(probe)
        login = probe.run(["sbx", "login", "status"])
        facts.sbx_logged_in = login.ok if login.returncode != 127 else None
        policy = probe.run(["sbx", "policy", "ls"])
        if policy.returncode == 127:
            facts.sbx_policy_initialized = None
        else:
            facts.sbx_policy_initialized = policy.ok and "not initialized" not in (policy.stdout + policy.stderr).lower()

    if probe.which("dpkg-query"):
        res = probe.run(["dpkg-query", "-W", "-f=${Version}", "obsidian"])
        if res.ok and res.stdout.strip():
            facts.obsidian_installed_version = res.stdout.strip()
    facts.python_version = (probe.env("STUDY_ROOM_FAKE_PYTHON") or platform.python_version())
    return facts


def _sbx_version(probe: Probe) -> str | None:
    res = probe.run(["sbx", "version", "--json"])
    if res.ok:
        try:
            data = json.loads(res.stdout)
            for key in ("version", "Version", "client", "Client"):
                value = data.get(key) if isinstance(data, dict) else None
                if isinstance(value, dict):
                    value = value.get("version") or value.get("Version")
                if isinstance(value, str):
                    return value.lstrip("v")
        except ValueError:
            pass
    res = probe.run(["sbx", "version"])
    if res.ok:
        for token in res.stdout.replace(",", " ").split():
            token = token.lstrip("v")
            if token[:1].isdigit() and token.count(".") >= 2:
                return token
    return None
