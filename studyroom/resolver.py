"""Host-side credential resolver for Docker Sandboxes' command-backed secrets (SPEC 15.4).

Docker Sandboxes runs ``<checkout>/bin/study-room resolve <name>`` on the host
whenever it needs the real value behind a sandbox placeholder. The contract:

* stdout carries exactly the value and a newline; nothing else is printed
  there. Messages go to stderr, redacted. Failures exit non-zero.
* It never prompts: a locked keyring or missing state fails with one line.
* OpenAI/Kimi: the structured OAuth state lives in Infisical at
  ``/study-room/oauth/<provider>/<installation-id>``. A token close to expiry
  is refreshed under an exclusive host lock; the state is re-read under the
  lock (another resolver may already have rotated it), the rotated state is
  written back in one replacement and read back to confirm, all before the
  lock is released. A refresh token is therefore never spent twice and never
  lost while another resolver waits.
* GitHub: the existing gej-machine PAT is read from its Infisical secret.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Callable, Protocol

from . import fsutil, redact
from .errors import Failure, fail
from .http import Client
from .oauth import kimi as kimi_oauth
from .oauth import openai as openai_oauth
from .oauth.state import OAuthState, parse
from .paths import HostPaths

MIN_VALID_SECONDS = 600  # longer than the sbx refresh interval (5m) plus slack
WRITE_ATTEMPTS = 3

Refresher = Callable[[Client, OAuthState], OAuthState]
REFRESHERS: dict[str, Refresher] = {"openai": openai_oauth.refresh, "kimi": kimi_oauth.refresh}


class Store(Protocol):
    def session_token(self) -> str: ...
    def revoke(self, token: str) -> None: ...
    def get(self, path: str, name: str, *, token: str | None = None) -> str | None: ...
    def put(self, path: str, name: str, value: str, *, exists: bool, token: str | None = None) -> None: ...


@dataclass
class OAuthLocation:
    path: str
    name: str


class Resolver:
    def __init__(
        self,
        store: Store,
        paths: HostPaths,
        installation_id: str,
        locations: dict[str, OAuthLocation],
        *,
        client: Client | None = None,
        refreshers: dict[str, Refresher] | None = None,
        clock: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
        min_valid_seconds: int = MIN_VALID_SECONDS,
        lock_timeout: float = 60,
    ):
        self.store = store
        self.paths = paths
        self.installation_id = installation_id
        self.locations = locations
        self.client = client or Client(timeout=30)
        self.refreshers = refreshers or REFRESHERS
        self.clock = clock
        self.sleep = sleep
        self.min_valid = min_valid_seconds
        self.lock_timeout = lock_timeout

    def _now_ms(self) -> int:
        return int(self.clock() * 1000)

    def _load(self, provider: str, token: str) -> OAuthState:
        loc = self.locations[provider]
        text = self.store.get(loc.path, loc.name, token=token)
        if text is None:
            raise fail(
                Failure.CREDENTIALS_NOT_CONFIGURED,
                f"{provider} is not authorized on this host",
                hint=f"run `study-room auth {provider}`",
            )
        return parse(text, provider=provider, installation_id=self.installation_id)

    def save_new(self, state: OAuthState) -> None:
        """Store the result of an interactive authorization (replacing any earlier state)."""
        loc = self.locations[state.provider]
        with fsutil.host_lock(self.paths.locks_dir / f"{state.provider}.lock", timeout=self.lock_timeout):
            token = self.store.session_token()
            try:
                existing = self.store.get(loc.path, loc.name, token=token)
                if existing is not None:
                    try:
                        previous = parse(existing, provider=state.provider, installation_id=self.installation_id)
                        state.generation = previous.generation + 1
                    except Exception:  # noqa: BLE001 - unreadable old state is simply replaced
                        pass
                self._write(state, exists=existing is not None, token=token)
            finally:
                self.store.revoke(token)

    def access_token(self, provider: str) -> str:
        if provider not in self.locations:
            raise fail(Failure.CONFIGURATION_INVALID, f"unknown provider {provider!r}")
        token = self.store.session_token()
        try:
            return self._access_token(provider, token)
        finally:
            self.store.revoke(token)

    def _access_token(self, provider: str, token: str) -> str:
        state = self._load(provider, token)
        if state.seconds_left(self._now_ms()) > self.min_valid:
            return state.access
        with fsutil.host_lock(self.paths.locks_dir / f"{provider}.lock", timeout=self.lock_timeout):
            # Another resolver may have rotated the state while we waited.
            state = self._load(provider, token)
            if state.seconds_left(self._now_ms()) > self.min_valid:
                return state.access
            rotated = self.refreshers[provider](self.client, state)
            if rotated.generation <= state.generation:
                raise fail(Failure.INTERNAL, "refresh did not advance the state generation")
            # The old refresh token may already be spent: persist before anything else.
            self._write(rotated, exists=True, token=token)
            return rotated.access

    def _write(self, state: OAuthState, *, exists: bool, token: str) -> None:
        loc = self.locations[state.provider]
        last: Exception | None = None
        for attempt in range(WRITE_ATTEMPTS):
            try:
                self.store.put(loc.path, loc.name, state.to_json(), exists=exists, token=token)
                stored = self.store.get(loc.path, loc.name, token=token)
                if stored is None:
                    raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, "the rotated state was not readable after writing")
                check = parse(stored, provider=state.provider, installation_id=self.installation_id)
                if check.generation != state.generation or check.refresh != state.refresh:
                    raise fail(
                        Failure.REFRESH_CONFLICT,
                        f"another writer replaced the {state.provider} state during refresh",
                        hint=f"run `study-room auth {state.provider}` if requests keep failing",
                    )
                return
            except Exception as exc:  # noqa: BLE001 - classified below
                last = exc
                if getattr(exc, "failure", None) == Failure.REFRESH_CONFLICT:
                    raise
                exists = True
                if attempt < WRITE_ATTEMPTS - 1:
                    self.sleep(2**attempt)
        raise fail(
            Failure.EXTERNAL_SERVICE_UNAVAILABLE,
            f"could not save the rotated {state.provider} authorization: {redact.redact_text(last)}",
            hint=f"the previous refresh token may already be spent; run `study-room auth {state.provider}`",
        )


def read_github_pat(store: Store, path: str, name: str) -> str:
    token = store.session_token()
    try:
        value = store.get(path, name, token=token)
    finally:
        store.revoke(token)
    if not value:
        raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, f"the GitHub token secret {name} was not found in Infisical at {path}")
    redact.register(value)
    return value.strip()
