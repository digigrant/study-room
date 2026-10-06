"""Study Room's own Secret Service namespace (SPEC 15.3).

The keyring holds only the handles needed to use the ``sbx-host`` Infisical
machine identity: project ID, client ID and client secret. Provider refresh
tokens never live here; they live in Infisical.

* Values are written with ``secret-tool store``, which reads them from stdin,
  never from an argument.
* The lock state is read with the Secret Service ``SearchItems`` D-Bus method
  through ``busctl``, which reports unlocked and locked items without loading
  a secret and without opening an unlock prompt. Non-interactive callers (the
  resolver run by Docker Sandboxes) therefore fail fast with one clear line
  instead of hanging on a prompt nobody can see.
* The service attribute is ``study-room``; it is independent of any other
  tool's namespace. ``STUDY_ROOM_KEYRING_SERVICE`` overrides it for tests.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from . import redact
from .errors import Failure, fail
from .runner import Runner

DEFAULT_SERVICE = "study-room"
KEYS = {
    "infisical-project-id": "Study Room Infisical project ID",
    "infisical-client-id": "Study Room Infisical sbx-host client ID",
    "infisical-client-secret": "Study Room Infisical sbx-host client secret",
}
# Optional: a separate Infisical project for Study Room's OAuth state, for
# deployments that isolate it by project instead of by path permissions.
OPTIONAL_KEYS = {
    "infisical-oauth-project-id": "Study Room Infisical project ID for OAuth state",
}
LOOKUP_TIMEOUT = 10


@dataclass
class ItemState:
    key: str
    state: str  # "unlocked", "locked" or "missing"


class Keyring:
    def __init__(self, runner: Runner | None = None, service: str | None = None):
        self.runner = runner or Runner()
        self.service = service or os.environ.get("STUDY_ROOM_KEYRING_SERVICE") or DEFAULT_SERVICE

    # --- availability ----------------------------------------------------
    def available(self) -> bool:
        return self.runner.which("secret-tool") is not None and self.runner.which("busctl") is not None

    def require_tools(self) -> None:
        missing = [tool for tool in ("secret-tool", "busctl") if self.runner.which(tool) is None]
        if missing:
            raise fail(
                Failure.MISSING_PREREQUISITE,
                f"{', '.join(missing)} not installed",
                hint="`study-room setup` installs libsecret-tools (secret-tool) and systemd (busctl)",
            )

    # --- state -----------------------------------------------------------
    def item_state(self, key: str) -> ItemState:
        res = self.runner.run(
            [
                "busctl", "--user", "call",
                "org.freedesktop.secrets", "/org/freedesktop/secrets",
                "org.freedesktop.Secret.Service", "SearchItems",
                "a{ss}", "2", "service", self.service, "key", key,
            ],
            timeout=LOOKUP_TIMEOUT,
        )
        if not res.ok:
            raise fail(
                Failure.MISSING_PREREQUISITE,
                "no Secret Service answered on the session bus",
                hint="start a desktop keyring (gnome-keyring) in this session; on WSL2 run `study-room setup`",
            )
        unlocked, locked = _parse_search_items(res.stdout)
        if unlocked:
            return ItemState(key, "unlocked")
        if locked:
            return ItemState(key, "locked")
        return ItemState(key, "missing")

    def states(self) -> dict[str, str]:
        return {key: self.item_state(key).state for key in KEYS}

    # --- read/write ------------------------------------------------------
    def lookup(self, key: str, *, interactive: bool = False) -> str:
        """Return a value. Non-interactive callers never trigger an unlock prompt."""
        state = self.item_state(key).state
        if state == "missing":
            raise fail(
                Failure.CREDENTIALS_NOT_CONFIGURED,
                f"keyring entry {key!r} is missing from the {self.service!r} namespace",
                hint="run `study-room setup` (Infisical step) to store the sbx-host handles",
            )
        if state == "locked" and not interactive:
            raise fail(
                Failure.CREDENTIALS_NOT_CONFIGURED,
                "the keyring is locked",
                hint="run `study-room run` or `study-room doctor` in a desktop session to unlock it",
            )
        res = self.runner.run(
            ["secret-tool", "lookup", "service", self.service, "key", key],
            timeout=180 if interactive else LOOKUP_TIMEOUT,
        )
        value = res.stdout.rstrip("\n")
        if not res.ok or not value:
            raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, f"could not read keyring entry {key!r}")
        redact.register(value)
        return value

    def store(self, key: str, value: str) -> None:
        if key not in KEYS and key not in OPTIONAL_KEYS:
            raise fail(Failure.INTERNAL, f"unknown keyring key {key!r}")
        if not value:
            raise fail(Failure.CONFIGURATION_INVALID, f"refusing to store an empty value for {key!r}")
        redact.register(value)
        res = self.runner.run(
            ["secret-tool", "store", f"--label={KEYS.get(key) or OPTIONAL_KEYS[key]}", "service", self.service, "key", key],
            input=value,
            timeout=180,
        )
        if not res.ok:
            raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, f"secret-tool could not store {key!r}: {res.stderr.strip()}")

    def unlock_interactively(self) -> None:
        """Open the Secret Service's own unlock prompt (a desktop window)."""
        for key in KEYS:
            if self.item_state(key).state == "locked":
                res = self.runner.run(
                    ["secret-tool", "lookup", "service", self.service, "key", key], timeout=180
                )
                if not res.ok:
                    raise fail(
                        Failure.CREDENTIALS_NOT_CONFIGURED,
                        "the keyring stayed locked",
                        hint="unlock it in the desktop prompt; a host with no display cannot show that prompt",
                    )
                return


_OBJ_PATH = re.compile(r'"(/[^"]*)"')


def _parse_search_items(stdout: str) -> tuple[list[str], list[str]]:
    """Parse busctl's ``aoao N "path"... M "path"...`` reply."""
    text = stdout.strip()
    if not text.startswith("aoao"):
        return [], []
    tokens = re.findall(r'"[^"]*"|\S+', text[len("aoao"):])
    unlocked: list[str] = []
    locked: list[str] = []
    idx = 0
    for bucket in (unlocked, locked):
        if idx >= len(tokens):
            break
        try:
            count = int(tokens[idx])
        except ValueError:
            break
        idx += 1
        for _ in range(count):
            if idx < len(tokens):
                bucket.append(tokens[idx].strip('"'))
                idx += 1
    return unlocked, locked
