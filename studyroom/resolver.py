"""Host-side credential resolver for Docker Sandboxes' command-backed secrets (SPEC 15.4).

Docker Sandboxes runs ``<checkout>/bin/study-room resolve <name>`` on the host
whenever it needs the real value behind a sandbox placeholder. The contract:

* stdout carries exactly the value and a newline; nothing else is printed
  there. Messages go to stderr, redacted. Failures exit non-zero.
* It never prompts: a locked keyring or missing state fails with one line.
* OpenAI/Kimi: the structured OAuth state lives in the provider's secret in
  the Agents Infisical project (OPENAI_REFRESH_TOKEN for OpenAI), one entry
  per installation ID. A token close to expiry is refreshed under an
  exclusive host lock; the entry is re-read under the lock (another resolver
  on this host may already have rotated it), then the rotated entry is merged
  into the latest document, written back in one replacement, and read back
  to confirm, all before the lock is released. If another host's write lands
  at the same time and drops this entry, the entry is merged in again. A
  refresh token is therefore never spent twice and never lost.
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
from .oauth.state import OAuthState, dump_document, entry, parse_document, with_entry
from .paths import HostPaths

MIN_VALID_SECONDS = 600  # longer than the sbx refresh interval (5m) plus slack
WRITE_ATTEMPTS = 4
SETTLE_SECONDS = 1.5  # second read-back: catches another host's write landing just after ours

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
        settle_seconds: float = SETTLE_SECONDS,
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
        self.settle = settle_seconds

    def _now_ms(self) -> int:
        return int(self.clock() * 1000)

    def _read(self, provider: str, token: str) -> tuple[str | None, dict, bool]:
        loc = self.locations[provider]
        text = self.store.get(loc.path, loc.name, token=token)
        doc, foreign = parse_document(text, provider)
        return text, doc, foreign

    def _load(self, provider: str, token: str) -> OAuthState:
        loc = self.locations[provider]
        _, doc, foreign = self._read(provider, token)
        if foreign:
            raise fail(
                Failure.CREDENTIALS_NOT_CONFIGURED,
                f"the Infisical secret {loc.name} holds a value Study Room did not write",
                hint=f"run `study-room auth {provider}` (it asks before replacing the value)",
            )
        state = entry(doc, provider, self.installation_id)
        if state is None:
            raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, f"{provider} is not authorized on this host", hint=f"run `study-room auth {provider}`")
        return state

    def save_new(self, state: OAuthState, *, replace_foreign: Callable[[], bool] = lambda: False) -> None:
        """Store the result of an interactive authorization for this installation."""
        with fsutil.host_lock(self.paths.locks_dir / f"{state.provider}.lock", timeout=self.lock_timeout):
            token = self.store.session_token()
            try:
                _, doc, foreign = self._read(state.provider, token)
                if foreign and not replace_foreign():
                    raise fail(
                        Failure.PERMISSION_DECLINED,
                        f"kept the existing value of {self.locations[state.provider].name}; the new authorization was not stored",
                    )
                previous = None if foreign else entry(doc, state.provider, self.installation_id)
                if previous is not None:
                    state.generation = previous.generation + 1
                self._write(state, token=token, replace_foreign=foreign)
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
            # Another resolver on this host may have rotated the state while we waited.
            state = self._load(provider, token)
            if state.seconds_left(self._now_ms()) > self.min_valid:
                return state.access
            rotated = self.refreshers[provider](self.client, state)
            if rotated.generation <= state.generation:
                raise fail(Failure.INTERNAL, "refresh did not advance the state generation")
            # The old refresh token may already be spent: persist before anything else.
            self._write(rotated, token=token)
            return rotated.access

    def _confirmed(self, state: OAuthState, token: str) -> bool:
        _, doc, foreign = self._read(state.provider, token)
        if foreign:
            return False
        stored = entry(doc, state.provider, self.installation_id)
        return stored is not None and stored.generation == state.generation and stored.refresh == state.refresh

    def _write(self, state: OAuthState, *, token: str, replace_foreign: bool = False) -> None:
        """Merge this installation's entry into the latest document and confirm it stuck."""
        loc = self.locations[state.provider]
        conflicts = 0
        last: Exception | None = None
        for attempt in range(WRITE_ATTEMPTS):
            try:
                text, doc, foreign = self._read(state.provider, token)
                if foreign and not replace_foreign:
                    raise fail(Failure.REFRESH_CONFLICT, f"{loc.name} was replaced by a value Study Room did not write during refresh")
                merged = with_entry(doc, state)
                self.store.put(loc.path, loc.name, dump_document(merged), exists=text is not None, token=token)
                replace_foreign = False
                if self._confirmed(state, token):
                    self.sleep(self.settle)
                    if self._confirmed(state, token):
                        return
                # Another host's concurrent write dropped this entry: merge again.
                conflicts += 1
                last = None
            except Exception as exc:  # noqa: BLE001 - classified below
                if getattr(exc, "failure", None) in (Failure.REFRESH_CONFLICT, Failure.CREDENTIALS_NOT_CONFIGURED, Failure.CONFIGURATION_INVALID):
                    raise
                last = exc
            if attempt < WRITE_ATTEMPTS - 1:
                self.sleep(2**attempt)
        if last is None and conflicts:
            raise fail(
                Failure.REFRESH_CONFLICT,
                f"another writer kept replacing {loc.name} during the {state.provider} refresh",
                hint=f"run `study-room auth {state.provider}` if requests keep failing",
            )
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
