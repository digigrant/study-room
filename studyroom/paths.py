"""XDG-oriented host paths (SPEC 8.2, 15.3).

Nothing here is hard-coded to a username or a Windows drive. Every location
derives from the XDG base-directory variables with their standard fallbacks,
so native Ubuntu and WSL2 share one layout.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

APP = "study-room"


def _xdg(var: str, fallback: str, env: dict[str, str]) -> Path:
    value = env.get(var, "")
    # The XDG spec says relative values are invalid and must be ignored.
    if value and os.path.isabs(value):
        return Path(value)
    home = env.get("HOME") or os.path.expanduser("~")
    return Path(home) / fallback


@dataclass(frozen=True)
class HostPaths:
    config_dir: Path
    state_dir: Path
    cache_dir: Path
    data_dir: Path

    @property
    def config_file(self) -> Path:
        return self.config_dir / "config.json"

    @property
    def locks_dir(self) -> Path:
        return self.state_dir / "locks"

    @property
    def receipts_dir(self) -> Path:
        return self.state_dir / "receipts"

    @property
    def log_file(self) -> Path:
        return self.state_dir / "study-room.log"

    @property
    def update_cache_file(self) -> Path:
        return self.cache_dir / "update-check.json"

    @property
    def downloads_dir(self) -> Path:
        return self.cache_dir / "downloads"

    @property
    def default_vault_dir(self) -> Path:
        return self.data_dir / "obsidian-vault"


def host_paths(env: dict[str, str] | None = None) -> HostPaths:
    env = dict(os.environ if env is None else env)
    return HostPaths(
        config_dir=_xdg("XDG_CONFIG_HOME", ".config", env) / APP,
        state_dir=_xdg("XDG_STATE_HOME", ".local/state", env) / APP,
        cache_dir=_xdg("XDG_CACHE_HOME", ".cache", env) / APP,
        data_dir=_xdg("XDG_DATA_HOME", ".local/share", env) / APP,
    )


def repo_root() -> Path:
    """The trusted infrastructure checkout this code runs from."""
    return Path(__file__).resolve().parent.parent
