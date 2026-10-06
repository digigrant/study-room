"""Secret redaction (SPEC 15.1, 21, 25.24).

Two layers:

* ``SecretRegistry`` remembers every secret value the current process has
  handled (access tokens, refresh tokens, client secrets, PATs). Any text that
  is about to be printed or logged is scrubbed of those exact values.
* Pattern redaction catches token-shaped strings and token-bearing JSON or
  form fields even when the value was never registered, for example inside an
  error body returned by a provider.

Redaction is applied to error messages, log lines, and diagnostics. It is a
backstop: code paths should also avoid formatting secrets in the first place.
"""

from __future__ import annotations

import re
import threading

REDACTED = "[REDACTED]"

# Values shorter than this are not registered: redacting "a" everywhere would
# destroy unrelated output, and real credentials are never this short.
_MIN_SECRET_LEN = 8

_TOKEN_FIELD_NAMES = (
    "access_token",
    "refresh_token",
    "id_token",
    "client_secret",
    "clientSecret",
    "accessToken",
    "refreshToken",
    "secretValue",
    "device_code",
    "code_verifier",
    "authorization_code",
    "access",
    "refresh",
    "password",
    "token",
    "apiKey",
    "api_key",
)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # JSON fields: "access_token": "....", including escaped quotes inside.
    (
        re.compile(
            r'("(?:%s)"\s*:\s*")((?:\\.|[^"\\]){8,})(")' % "|".join(_TOKEN_FIELD_NAMES)
        ),
        r"\1" + REDACTED + r"\3",
    ),
    # Form / query fields: access_token=...&
    (
        re.compile(r"\b((?:%s)=)([^&\s\"']{8,})" % "|".join(_TOKEN_FIELD_NAMES)),
        r"\1" + REDACTED,
    ),
    # Authorization headers.
    (re.compile(r"(?i)\b(authorization\s*:\s*(?:bearer|basic|token)\s+)([^\s\"',]+)"), r"\1" + REDACTED),
    (re.compile(r"(?i)\b(bearer\s+)([A-Za-z0-9._~+/=-]{8,})"), r"\1" + REDACTED),
    # JWTs (three base64url segments, first one a JSON header).
    (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}"), REDACTED),
    # GitHub tokens.
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b"), REDACTED),
    (re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"), REDACTED),
    # OpenAI / Anthropic style keys.
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), REDACTED),
]


class SecretRegistry:
    def __init__(self) -> None:
        self._values: set[str] = set()
        self._lock = threading.Lock()

    def add(self, value: object) -> None:
        if not isinstance(value, str):
            return
        value = value.strip()
        if len(value) < _MIN_SECRET_LEN:
            return
        with self._lock:
            self._values.add(value)

    def add_mapping(self, mapping: object) -> None:
        """Register every string leaf of a structured secret (OAuth state)."""
        if isinstance(mapping, dict):
            for key, value in mapping.items():
                if isinstance(value, (dict, list)):
                    self.add_mapping(value)
                elif _is_secret_key(str(key)):
                    self.add(value)
        elif isinstance(mapping, list):
            for item in mapping:
                self.add_mapping(item)

    def scrub(self, text: str) -> str:
        with self._lock:
            values = sorted(self._values, key=len, reverse=True)
        for value in values:
            if value in text:
                text = text.replace(value, REDACTED)
        return text

    def clear(self) -> None:
        with self._lock:
            self._values.clear()


_SECRET_KEY_HINTS = ("token", "secret", "access", "refresh", "password", "key", "verifier", "code")


def _is_secret_key(key: str) -> bool:
    lowered = key.lower()
    if lowered in {"expires", "expires_at", "expires_in", "token_type", "scope", "scopes", "keyid"}:
        return False
    return any(hint in lowered for hint in _SECRET_KEY_HINTS)


REGISTRY = SecretRegistry()


def register(value: object) -> None:
    REGISTRY.add(value)


def register_mapping(mapping: object) -> None:
    REGISTRY.add_mapping(mapping)


def redact_text(text: object) -> str:
    if text is None:
        return ""
    out = REGISTRY.scrub(str(text))
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def contains_secret(text: str) -> bool:
    """True if redaction would change ``text`` (used by tests and log guards)."""
    return redact_text(text) != text
