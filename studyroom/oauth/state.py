"""Structured provider OAuth state, as stored in Infisical (SPEC 15.4 step 3).

One JSON value per provider and installation holds everything the pinned
provider implementation needs, so a rotation replaces it in a single write.
``generation`` increases with every rotation; the resolver uses it to detect
that another writer replaced the state while it was refreshing.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field

from .. import redact
from ..errors import Failure, fail

SCHEMA = 1


@dataclass
class OAuthState:
    provider: str  # openai | kimi
    installation_id: str
    access: str
    refresh: str
    expires_ms: int  # epoch milliseconds, already reduced by the provider's safety margin
    client_id: str | None = None
    scopes: list[str] = field(default_factory=list)
    account: dict = field(default_factory=dict)  # non-secret account metadata the provider needs
    obtained_at_ms: int = 0
    rotated_at_ms: int = 0
    generation: int = 1
    schema: int = SCHEMA

    def __post_init__(self) -> None:
        redact.register(self.access)
        redact.register(self.refresh)

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True, separators=(",", ":"))

    def seconds_left(self, now_ms: int | None = None) -> float:
        now_ms = int(time.time() * 1000) if now_ms is None else now_ms
        return (self.expires_ms - now_ms) / 1000

    def rotated(self, access: str, refresh: str, expires_ms: int, now_ms: int, **changes) -> "OAuthState":
        data = asdict(self)
        data.update(changes)
        data.update(access=access, refresh=refresh, expires_ms=expires_ms, rotated_at_ms=now_ms, generation=self.generation + 1)
        return OAuthState(**data)

    def describe(self) -> str:
        """Non-secret summary for status output."""
        left = self.seconds_left()
        when = f"expires in {int(left // 60)} min" if left > 0 else "access token expired (refresh pending)"
        return f"{self.provider}: generation {self.generation}, {when}, client {'issued' if self.client_id else 'n/a'}"


def parse(text: str, *, provider: str, installation_id: str) -> OAuthState:
    try:
        data = json.loads(text)
    except ValueError:
        raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, f"stored {provider} authorization state is not valid JSON") from None
    if not isinstance(data, dict) or data.get("schema") != SCHEMA:
        raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, f"stored {provider} authorization state has an unknown schema")
    redact.register_mapping(data)
    if data.get("provider") != provider or data.get("installation_id") != installation_id:
        raise fail(
            Failure.CREDENTIALS_NOT_CONFIGURED,
            f"stored {provider} authorization state belongs to another provider or installation",
            hint=f"run `study-room auth {provider}` on this host",
        )
    for key in ("access", "refresh"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, f"stored {provider} authorization state lacks {key}")
    if not isinstance(data.get("expires_ms"), int):
        raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, f"stored {provider} authorization state lacks an expiry")
    known = set(OAuthState.__dataclass_fields__)
    return OAuthState(**{k: v for k, v in data.items() if k in known})


# ── The stored document ─────────────────────────────────────────────────────
#
# By the captain's decision (2026-10-06) each provider's OAuth state lives in
# one existing secret in the Agents project (OPENAI_REFRESH_TOKEN for OpenAI).
# Several hosts (WSL2, native Ubuntu) may use the same secret, and each must
# rotate independently (SPEC 15.2), so the value is a document with one entry
# per installation ID. A host only ever changes its own entry.

DOC_KIND = "study-room-oauth"


def empty_document(provider: str) -> dict:
    return {"kind": DOC_KIND, "schema": SCHEMA, "provider": provider, "installations": {}}


def parse_document(text: str | None, provider: str) -> tuple[dict, bool]:
    """Return (document, foreign). A missing or blank value is a fresh document;
    a value Study Room did not write is reported as foreign, never reused."""
    if text is None or not text.strip():
        return empty_document(provider), False
    try:
        data = json.loads(text)
    except ValueError:
        redact.register(text.strip())  # e.g. a bare token pasted by hand: still a secret
        return empty_document(provider), True
    if not isinstance(data, dict) or data.get("kind") != DOC_KIND or data.get("provider") != provider or not isinstance(data.get("installations"), dict):
        redact.register_mapping(data)
        return empty_document(provider), True
    redact.register_mapping(data)
    return data, False


def entry(document: dict, provider: str, installation_id: str) -> OAuthState | None:
    raw = document.get("installations", {}).get(installation_id)
    if raw is None:
        return None
    return parse(json.dumps(raw), provider=provider, installation_id=installation_id)


def with_entry(document: dict, state: OAuthState) -> dict:
    doc = json.loads(json.dumps(document))
    doc["installations"][state.installation_id] = asdict(state)
    return doc


def dump_document(document: dict) -> str:
    return json.dumps(document, sort_keys=True, separators=(",", ":"))
