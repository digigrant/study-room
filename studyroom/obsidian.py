"""Linux Obsidian Desktop: pinned install, vault onboarding, launch (SPEC 8).

Obsidian runs on the host, never in the sandbox. It owns the complete local
vault replica, the account and Sync credentials, ``.obsidian`` and the
encryption state; only the vault's ``Study Room/`` directory is mounted into
the sandbox. Sign-in, Sync sign-in, encryption-key entry and remote-vault
selection stay interactive ceremonies performed by the user in Obsidian.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .config import Config
from .errors import Failure, fail
from .paths import HostPaths
from .runner import Runner

APP_BINARY = "/opt/Obsidian/obsidian"


def installed_version(runner: Runner) -> str | None:
    res = runner.run(["dpkg-query", "-W", "-f=${Version}", "obsidian"], timeout=20)
    return res.stdout.strip() if res.ok and res.stdout.strip() else None


def deb_path(paths: HostPaths, pin: dict) -> Path:
    return paths.downloads_dir / Path(urllib.parse.urlsplit(pin["url"]).path).name


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def download(paths: HostPaths, pin: dict, *, opener=urllib.request.urlopen, say=print) -> Path:
    """Fetch the pinned .deb into the cache and verify its checksum (no sudo)."""
    target = deb_path(paths, pin)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists() and sha256_file(target) == pin["sha256"]:
        return target
    tmp = target.with_suffix(".part")
    say(f"Downloading Obsidian {pin['version']} from {pin['url']}")
    with opener(pin["url"], timeout=120) as resp, open(tmp, "wb") as out:  # noqa: S310 - pinned https URL
        shutil.copyfileobj(resp, out)
    actual = sha256_file(tmp)
    if actual != pin["sha256"]:
        tmp.unlink(missing_ok=True)
        raise fail(
            Failure.PIN_MISMATCH,
            f"Obsidian {pin['version']} checksum mismatch: got {actual}, the lock pins {pin['sha256']}",
            hint="nothing was installed; a different artifact is never substituted",
        )
    tmp.replace(target)
    return target


def install_argv(deb: Path) -> list[str]:
    return ["sudo", "apt-get", "install", "-y", "--no-install-recommends", str(deb)]


@dataclass
class VaultStatus:
    ok: bool
    problems: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if self.ok:
            return "Obsidian vault ready" + (f" ({'; '.join(self.warnings)})" if self.warnings else "")
        return "Obsidian not ready: " + "; ".join(self.problems)


def _inside_git(runner: Runner, path: Path) -> bool:
    if not path.exists():
        return False
    res = runner.run(["git", "-C", str(path), "rev-parse", "--is-inside-work-tree"], timeout=20)
    return res.ok and res.stdout.strip() == "true"


def registered_vaults(home: Path) -> list[str]:
    data_file = home / ".config" / "obsidian" / "obsidian.json"
    try:
        data = json.loads(data_file.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    vaults = data.get("vaults", {}) if isinstance(data, dict) else {}
    return [str(v.get("path")) for v in vaults.values() if isinstance(v, dict) and v.get("path")]


def vault_status(config: Config, runner: Runner, home: Path | None = None) -> VaultStatus:
    home = home or Path(os.path.expanduser("~"))
    st = VaultStatus(ok=True)
    vault, study = config.vault_path, config.study_dir
    if "\\" in str(vault) or re.match(r"^/mnt/[A-Za-z](/|$)", str(vault)):
        st.problems.append(f"{vault} is on a Windows drive; Study Room uses a fresh Linux replica (SPEC 8.2)")
    if not vault.is_dir():
        st.problems.append(f"vault directory {vault} does not exist")
    else:
        if not (vault / ".obsidian").is_dir():
            st.problems.append(f"{vault} has not been opened as an Obsidian vault yet")
        if not study.is_dir():
            st.problems.append(f"{study} does not exist in the vault")
        if _inside_git(runner, vault) or (vault / ".git").exists() or (study / ".git").exists():
            st.problems.append("the vault or Study Room/ is inside a Git repository; the vault must not be a Git repository (SPEC 9.1)")
        if str(vault) not in registered_vaults(home):
            st.warnings.append("Obsidian has not registered this vault path yet")
        core = vault / ".obsidian" / "core-plugins.json"
        try:
            plugins = json.loads(core.read_text(encoding="utf-8"))
            enabled = plugins if isinstance(plugins, list) else [k for k, v in plugins.items() if v]
            if "sync" not in enabled:
                st.warnings.append("the Sync core plugin is not enabled in this vault")
        except (OSError, ValueError):
            pass
    st.ok = not st.problems
    return st


def running(runner: Runner) -> bool:
    res = runner.run(["pgrep", "-u", str(os.getuid()), "-f", APP_BINARY], timeout=10)
    return res.ok and bool(res.stdout.strip())


def open_uri(vault: Path) -> str:
    return "obsidian://open?" + urllib.parse.urlencode({"path": str(vault)}, quote_via=urllib.parse.quote)


def start_or_reuse(config: Config, runner: Runner, *, say=print) -> str:
    """Start Obsidian with the configured vault, or leave a healthy instance alone (SPEC 8.5)."""
    if running(runner):
        return "Obsidian is already running (left as is)"
    binary = runner.which("obsidian") or (APP_BINARY if Path(APP_BINARY).exists() else None)
    if not binary:
        raise fail(Failure.OBSIDIAN_NOT_CONFIGURED, "Obsidian Desktop is not installed", hint="run `study-room setup`")
    if not (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")):
        raise fail(Failure.MISSING_PREREQUISITE, "no graphical session (DISPLAY/WAYLAND_DISPLAY) for Obsidian", hint="run from the desktop session, or use --no-obsidian")
    runner.spawn_detached([binary, open_uri(config.vault_path)])
    say(f"Started Obsidian with {config.vault_path}")
    return "Obsidian started"


ONBOARDING = """\
Obsidian Sync onboarding (you do these steps in Obsidian; Study Room never sees your credentials):

  1. Study Room created an empty folder for the new Linux replica:
       {vault}
     Do not point it at the Windows vault directory; Windows Obsidian keeps its own replica.
  2. In Obsidian choose "Open folder as vault" and select that folder.
  3. Settings → Core plugins → enable Sync. Settings → Sync → sign in to your Obsidian account.
  4. Choose your existing remote vault, enter its encryption password when asked, and connect.
  5. Wait until Sync reports it is fully synced.
  6. Make sure the vault contains a folder named "{study_dir}". Pi will see only that folder.

Lesson logs: create a new, empty note for /md-log, and keep it view-only while logging is active.
"""
