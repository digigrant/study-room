"""Host egress guard for the Docker Sandboxes daemon (SPEC 12.2/13, decision 2).

Docker Sandboxes ends every sandbox's network traffic in the host daemon's
userspace network stack and opens the real connections from that daemon, so
a public host name that resolves to a home-network address would be reached
by the daemon itself. Docker Sandboxes' own policy cannot stop that: it does
not check an allowed host name's resolved address against CIDR rules.

By the captain's decision (2026-10-06) the daemon therefore runs inside a
managed systemd user unit, ``study-room-sbx.service``, whose start loads a
host firewall rule matching that unit's cgroup (host/sbx-egress-guard). The
rule rejects the daemon's connections to private, link-local, CGNAT
(Tailscale) and IPv6 ULA/link-local ranges. It covers every Docker Sandbox
this user runs, not only Study Room's; the captain accepted that. Processes
outside the unit (tailscaled, the Magic Conch hub, the user's own programs)
are not matched.

Entry fails closed unless the daemon runs inside the unit and the rule is
loaded for the unit's current cgroup.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shlex
import socket
import subprocess
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterable

from .errors import Failure, fail
from .paths import HostPaths, repo_root
from .runner import Runner

UNIT = "study-room-sbx.service"
SLICE = "study-room.slice"
GUARD_INSTALL_PATH = "/usr/local/libexec/study-room/sbx-egress-guard"
SUDOERS_PATH = "/etc/sudoers.d/study-room-egress"
STATUS_FILE = "/run/study-room/sbx-egress.json"
_USER_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")


def guard_source() -> Path:
    return repo_root() / "host" / "sbx-egress-guard"


def cgroup_path(uid: int) -> str:
    """The managed unit's cgroup, relative to the cgroup v2 root."""
    return f"user.slice/user-{uid}.slice/user@{uid}.service/{SLICE}/{UNIT}"


def user_unit_dir(home: Path) -> Path:
    return home / ".config" / "systemd" / "user"


def render_slice() -> str:
    return "[Unit]\nDescription=Study Room: Docker Sandboxes daemon (egress-guarded)\nDocumentation=https://github.com/digigrant/study-room/blob/main/docs/SECURITY.md\n"


def render_unit(*, sbx_bin: str, guard: str = GUARD_INSTALL_PATH) -> str:
    return "\n".join(
        [
            "# Written by `study-room setup`. Runs the Docker Sandboxes daemon in its own",
            "# cgroup and loads the host egress guard for that cgroup before it starts",
            "# (docs/SECURITY.md, Network egress guard). Do not start the daemon any",
            "# other way: `study-room run` refuses a daemon running outside this unit.",
            "[Unit]",
            "Description=Docker Sandboxes daemon with the Study Room egress guard",
            "Documentation=https://github.com/digigrant/study-room/blob/main/docs/SECURITY.md",
            "",
            "[Service]",
            "Type=simple",
            f"Slice={SLICE}",
            f"ExecStartPre=/usr/bin/sudo -n {guard} load",
            f"ExecStart={sbx_bin} daemon start",
            f"ExecStopPost=/usr/bin/sudo -n {guard} unload",
            "Restart=on-failure",
            "RestartSec=5",
            "",
            "[Install]",
            "WantedBy=default.target",
            "",
        ]
    )


def render_sudoers(user: str, guard: str = GUARD_INSTALL_PATH) -> str:
    if not _USER_RE.match(user or "") or user == "root":
        raise fail(Failure.CONFIGURATION_INVALID, f"refusing to write a sudoers rule for user {user!r}")
    return (
        "# Written by `study-room setup`: lets the study-room-sbx.service user unit load\n"
        "# and unload its host egress guard (docs/SECURITY.md). Nothing else.\n"
        f"{user} ALL=(root) NOPASSWD: {guard} load, {guard} unload, {guard} status\n"
    )


# ── Health checks (doctor and run) ─────────────────────────────────────────


@dataclass(frozen=True)
class Problem:
    code: str
    message: str
    hint: str


def _read(path: Path) -> str | None:
    try:
        return path.read_bytes().decode(errors="replace")
    except OSError:
        return None


def _cgroup_of(proc: Path, pid: int) -> str | None:
    text = _read(proc / str(pid) / "cgroup")
    if not text:
        return None
    for line in text.splitlines():
        if line.startswith("0::"):
            return line[3:].strip().lstrip("/")
    return None


def _pids(proc: Path) -> Iterable[int]:
    try:
        names = os.listdir(proc)
    except OSError:
        return []
    return sorted(int(n) for n in names if n.isdigit())


def daemon_pids(proc_root: Path | str = "/proc") -> list[int]:
    """Processes running `sbx daemon start` (the Docker Sandboxes daemon)."""
    proc = Path(proc_root)
    out = []
    for pid in _pids(proc):
        raw = _read(proc / str(pid) / "cmdline")
        if not raw:
            continue
        argv = [a for a in raw.split("\0") if a]
        if argv and Path(argv[0]).name == "sbx" and argv[1:3] == ["daemon", "start"]:
            out.append(pid)
    return out


def processes_named(proc_root: Path | str, names: Iterable[str], cmd_contains: str | None = None) -> list[int]:
    proc = Path(proc_root)
    wanted = set(names)
    out = []
    for pid in _pids(proc):
        comm = (_read(proc / str(pid) / "comm") or "").strip()
        raw = _read(proc / str(pid) / "cmdline") or ""
        argv = [a for a in raw.split("\0") if a]
        base = Path(argv[0]).name if argv else ""
        if comm in wanted or base in wanted:
            if cmd_contains is None or cmd_contains in " ".join(argv):
                out.append(pid)
    return out


def check(
    uid: int,
    *,
    runner: Runner,
    proc_root: Path | str = "/proc",
    cgroup_root: Path | str = "/sys/fs/cgroup",
    status_file: Path | str = STATUS_FILE,
) -> list[Problem]:
    problems: list[Problem] = []
    restart = f"systemctl --user restart {UNIT}"
    expected = cgroup_path(uid)
    active = runner.run(["systemctl", "--user", "is-active", UNIT], timeout=20)
    if active.stdout.strip() != "active":
        problems.append(Problem("unit_inactive", f"{UNIT} is not running", f"systemctl --user enable --now {UNIT} (installed by `study-room setup`)"))
    proc = Path(proc_root)
    pids = daemon_pids(proc)
    if not pids:
        problems.append(Problem("daemon_not_running", "the Docker Sandboxes daemon is not running", restart))
    outside = [p for p in pids if _cgroup_of(proc, p) != expected]
    if outside:
        problems.append(
            Problem(
                "daemon_outside_unit",
                f"the Docker Sandboxes daemon (pid {', '.join(map(str, outside))}) runs outside {UNIT}, so the egress guard does not cover it",
                f"sbx daemon stop; {restart}",
            )
        )
    live = runner.run(["sudo", "-n", GUARD_INSTALL_PATH, "status"], timeout=30)
    loaded = re.search(r"^loaded cgroup=(\S+)", live.stdout or "", re.M)
    status_text = _read(Path(status_file))
    if not live.ok or not loaded or loaded.group(1) != expected or status_text is None:
        problems.append(Problem("guard_not_loaded", "the host egress guard's firewall rules are not loaded for the daemon's unit", restart))
    else:
        try:
            status = json.loads(status_text)
        except ValueError:
            status = {}
        try:
            current = (Path(cgroup_root) / expected).stat().st_ino
        except OSError:
            current = None
        if status.get("cgroup") != expected or status.get("cgroup_inode") != current:
            problems.append(Problem("guard_stale", "the host egress guard was loaded for another daemon instance", restart))
    return problems


# ── Installation state and setup ───────────────────────────────────────────


@dataclass(frozen=True)
class InstallState:
    guard_ok: bool
    sudoers_ok: bool
    unit_ok: bool
    enabled: bool

    @property
    def ready(self) -> bool:
        return self.guard_ok and self.sudoers_ok and self.unit_ok and self.enabled


def _same(path: Path, content: bytes) -> bool:
    try:
        return hashlib.sha256(path.read_bytes()).digest() == hashlib.sha256(content).digest()
    except OSError:
        return False


def install_state(
    paths: HostPaths,
    user: str,
    runner: Runner,
    *,
    sbx_bin: str,
    guard_path: Path | str = GUARD_INSTALL_PATH,
    sudoers_path: Path | str = SUDOERS_PATH,
    unit_dir: Path | None = None,
) -> InstallState:
    unit_dir = unit_dir or user_unit_dir(Path(os.path.expanduser("~")))
    guard_ok = _same(Path(guard_path), guard_source().read_bytes())
    sudoers_ok = _same(Path(sudoers_path), render_sudoers(user).encode())
    unit_ok = _same(unit_dir / UNIT, render_unit(sbx_bin=sbx_bin).encode()) and _same(unit_dir / SLICE, render_slice().encode())
    enabled = runner.run(["systemctl", "--user", "is-enabled", UNIT], timeout=20).stdout.strip() == "enabled"
    del paths
    return InstallState(guard_ok, sudoers_ok, unit_ok, enabled)


def setup_commands(paths: HostPaths, user: str, *, sbx_bin: str, home: Path | None = None) -> tuple[list[list[str]], Callable[[], None]]:
    """The approved change's commands, and the non-sudo preparation that writes the user unit files."""
    home = home or Path(os.path.expanduser("~"))
    staged = paths.cache_dir / "study-room-egress.sudoers"
    unit_dir = user_unit_dir(home)

    def prepare() -> None:
        paths.cache_dir.mkdir(parents=True, exist_ok=True)
        staged.write_text(render_sudoers(user))
        unit_dir.mkdir(parents=True, exist_ok=True)
        (unit_dir / SLICE).write_text(render_slice())
        (unit_dir / UNIT).write_text(render_unit(sbx_bin=sbx_bin))

    commands = [
        ["sudo", "install", "-D", "-m", "0755", "-o", "root", "-g", "root", str(guard_source()), GUARD_INSTALL_PATH],
        ["sudo", "visudo", "-cf", str(staged)],
        ["sudo", "install", "-m", "0440", "-o", "root", "-g", "root", str(staged), SUDOERS_PATH],
        ["sh", "-c", "sbx daemon stop || true"],  # a daemon started any other way must not keep running
        ["systemctl", "--user", "daemon-reload"],
        ["systemctl", "--user", "enable", "--now", UNIT],
    ]
    return commands, prepare


# ── Live verification (`study-room verify --live egress`) ──────────────────

TEST_IFACE = "sr-egress-test"
TEST_IP = "10.213.0.1"
TEST_PORT = 8471
TEST_HOSTNAME = "10-213-0-1.sslip.io"  # public wildcard DNS that answers with the embedded address
PUBLIC_URL = "https://api.github.com/"


class _Server:
    def __init__(self, proc: subprocess.Popen):
        self.proc = proc

    def stop(self) -> None:
        self.proc.terminate()
        try:
            self.proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.proc.kill()


def start_http_server(ip: str, port: int) -> _Server:
    proc = subprocess.Popen(
        ["python3", "-m", "http.server", str(port), "--bind", ip],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    return _Server(proc)


def host_http_get(url: str) -> int | None:
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(url, timeout=5) as resp:  # noqa: S310 - fixed local test URL
            return resp.status
    except Exception:  # noqa: BLE001 - any failure means "not reachable"
        return None


def host_tcp_connect(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=5):
            return True
    except OSError:
        return False


def host_resolve(name: str) -> list[str]:
    try:
        return sorted({a[4][0] for a in socket.getaddrinfo(name, None, socket.AF_INET)})
    except OSError:
        return []


def live_verify(
    runner: Runner,
    sandbox: str,
    *,
    uid: int,
    confirm: Callable[[list[str]], bool],
    say: Callable[[str], None] = print,
    proc_root: Path | str = "/proc",
    check: Callable[[], list[Problem]] | None = None,
    http_get: Callable[[str], int | None] = host_http_get,
    tcp_connect: Callable[[str, int], bool] = host_tcp_connect,
    resolve: Callable[[str], list[str]] = host_resolve,
    start_server: Callable[[str, int], object] = start_http_server,
    tailscale_peer: str | None = None,
    hub_port: int = 8431,
) -> dict[str, str]:
    """Prove the guard blocks the sandbox from a private address while host traffic,
    Tailscale and the Magic Conch hub keep working. Every step reports passed, failed
    or skipped (with its reason); temporary changes are always undone."""
    peer_host, peer_port = (tailscale_peer.rsplit(":", 1)[0], int(tailscale_peer.rsplit(":", 1)[1])) if tailscale_peer else (None, None)
    lines = [
        "Egress guard live check (no provider requests):",
        f"  1. create a dummy interface {TEST_IFACE} with {TEST_IP} and a test web server on port {TEST_PORT} (sudo)",
        f"  2. temporarily allow {TEST_IP}:{TEST_PORT} and {TEST_HOSTNAME}:{TEST_PORT} in the {sandbox} sandbox's own policy",
        "  3. expect the host to reach it and the host guard to reject the sandbox; expect the sandbox to reach api.github.com",
        "  4. check that tailscaled and the Magic Conch hub run outside the daemon's unit and still work",
    ]
    if tailscale_peer:
        lines.append(f"  5. Tailscale peer {tailscale_peer}: reachable from the host, rejected by the host guard from the sandbox (temporary allow)")
    lines.append("  Everything temporary is removed afterwards.")
    if not confirm(lines):
        raise fail(Failure.PERMISSION_DECLINED, "egress live check not confirmed; nothing changed")
    results: dict[str, str] = {}

    def record(name: str, status: str, detail: str) -> None:
        results[name] = status
        say(f"  {name}: {status} - {detail}")

    problems = (check or (lambda: check_default(uid, runner)))()
    if problems:
        record("guard", "failed", "; ".join(p.message for p in problems))
        return results
    record("guard", "passed", f"the daemon runs inside {UNIT} and the guard is loaded for its cgroup")

    expected = cgroup_path(uid)
    proc = Path(proc_root)
    for name, pids, label in (
        ("tailscale_cgroup", processes_named(proc, ["tailscaled"]), "tailscaled"),
        ("hub_cgroup", processes_named(proc, ["docker-proxy", "magic-conch"], cmd_contains=str(hub_port)) or processes_named(proc, ["magic-conch", "magic-conch-hub"]), "the Magic Conch hub"),
    ):
        if not pids:
            record(name, "skipped", f"{label} is not running on this host")
        elif any(_cgroup_of(proc, p) == expected or (_cgroup_of(proc, p) or "").startswith(expected + "/") for p in pids):
            record(name, "failed", f"{label} runs inside {UNIT}; the guard would cover it")
        else:
            record(name, "passed", f"{label} runs in {sorted({_cgroup_of(proc, p) for p in pids})}, outside the daemon's unit")

    temp_rules: list[str] = []
    server = None
    iface_created = False

    def allow(resource: str) -> None:
        runner.run(["sbx", "policy", "allow", "network", "--sandbox", sandbox, resource], timeout=60)
        temp_rules.append(resource)

    def sandbox_code(url: str) -> str:
        res = runner.run(["sbx", "exec", sandbox, "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "--max-time", "15", url], timeout=60)
        return (res.stdout or "").strip() or f"exit {res.returncode}"

    def rejected() -> int:
        res = runner.run(["sudo", "-n", GUARD_INSTALL_PATH, "status"], timeout=30)
        m = re.search(r"rejected=(\d+)", res.stdout or "")
        return int(m.group(1)) if m else -1

    def guarded(name: str, url: str, label: str) -> None:
        before = rejected()
        code = sandbox_code(url)
        after = rejected()
        seen = f"sandbox -> {label}: {code}, guard rejections {before} -> {after}"
        if code == "200":
            record(name, "failed", f"{seen}; the sandbox reached it")
        elif code == "403" or code.startswith("exit"):
            record(name, "failed", f"{seen}; refused by Docker Sandboxes' own policy or the exec failed, so the host guard was not exercised")
        elif not after > before >= 0:
            record(name, "failed", f"{seen}; the guard did not reject this request")
        else:
            record(name, "passed", f"{seen}; rejected by the host guard")

    try:
        for argv in (
            ["sudo", "ip", "link", "add", TEST_IFACE, "type", "dummy"],
            ["sudo", "ip", "addr", "add", f"{TEST_IP}/32", "dev", TEST_IFACE],
            ["sudo", "ip", "link", "set", TEST_IFACE, "up"],
        ):
            res = runner.run(argv, timeout=60)
            iface_created = True
            if not res.ok:
                raise fail(Failure.MISSING_PREREQUISITE, f"`{shlex.join(argv)}` failed: {(res.stderr or '').strip()[:120]}")
        server = start_server(TEST_IP, TEST_PORT)
        url = f"http://{TEST_IP}:{TEST_PORT}/"
        host = http_get(url)
        record("host_private", "passed" if host == 200 else "failed", f"host process -> {url}: {host}")
        allow(f"{TEST_IP}:{TEST_PORT}")
        guarded("sandbox_private_literal", url, url)
        if TEST_IP in resolve(TEST_HOSTNAME):
            allow(f"{TEST_HOSTNAME}:{TEST_PORT}")
            guarded("sandbox_private_hostname", f"http://{TEST_HOSTNAME}:{TEST_PORT}/", f"{TEST_HOSTNAME} (resolves to {TEST_IP})")
        else:
            record("sandbox_private_hostname", "skipped", f"{TEST_HOSTNAME} does not resolve to {TEST_IP} from this host")
        code = sandbox_code(PUBLIC_URL)
        record("sandbox_public", "passed" if code == "200" else "failed", f"sandbox -> {PUBLIC_URL}: {code}")
        if runner.which("tailscale"):
            ts = runner.run(["tailscale", "status", "--json"], timeout=30)
            try:
                state = json.loads(ts.stdout or "{}").get("BackendState")
            except ValueError:
                state = None
            record("tailscale_running", "passed" if state == "Running" else "failed", f"tailscale BackendState={state}")
        else:
            record("tailscale_running", "skipped", "tailscale is not installed")
        if peer_host:
            ok = tcp_connect(peer_host, peer_port)
            record("tailscale_host_peer", "passed" if ok else "failed", f"host -> {tailscale_peer}: {'connected' if ok else 'unreachable'}")
            allow(f"{peer_host}:{peer_port}")
            guarded("sandbox_tailscale_peer", f"http://{peer_host}:{peer_port}/", tailscale_peer)
        else:
            record("tailscale_host_peer", "skipped", "no --tailscale-peer HOST:PORT given")
        if tcp_connect("127.0.0.1", hub_port):
            record("hub_session_port", "passed", f"host -> 127.0.0.1:{hub_port} (Magic Conch session listener) connected")
        else:
            record("hub_session_port", "skipped", f"nothing listens on 127.0.0.1:{hub_port}")
    finally:
        for resource in temp_rules:
            runner.run(["sbx", "policy", "rm", "network", "--sandbox", sandbox, "--resource", resource, "-f"], timeout=60)
        if server is not None:
            server.stop()  # type: ignore[attr-defined]
        if iface_created:
            runner.run(["sudo", "ip", "link", "del", TEST_IFACE], timeout=60)
    return results


def check_default(uid: int, runner: Runner) -> list[Problem]:
    return check(uid, runner=runner)
