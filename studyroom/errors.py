"""Classified failures (SPEC 21).

Every failure the host command reports is a ``StudyRoomError`` carrying one
of the classes below, so a user (and the tests) can tell a missing host
prerequisite from a declined permission or a pin mismatch. Messages are
passed through redaction before they are rendered, so no failure path can
print a token or a structured secret.
"""

from __future__ import annotations

import enum

from . import redact


class Failure(enum.Enum):
    MISSING_PREREQUISITE = "missing host prerequisite"
    PERMISSION_DECLINED = "permission declined"
    UNSUPPORTED_PLATFORM = "unsupported platform"
    PIN_MISMATCH = "pin/checksum mismatch"
    PROVIDER_UNAVAILABLE = "provider unavailable"
    CREDENTIALS_NOT_CONFIGURED = "credentials not configured"
    AUTHORIZATION_EXPIRED = "authorization expired or revoked"
    REFRESH_CONFLICT = "refresh conflict"
    EXTERNAL_SERVICE_UNAVAILABLE = "external service unavailable"
    MODEL_NOT_IN_CATALOG = "model absent from authenticated catalog"
    SEARCH_UNSUPPORTED = "search unsupported"
    NETWORK_POLICY_BLOCKED = "network policy blocked destination"
    OBSIDIAN_NOT_CONFIGURED = "Obsidian not configured"
    VAULT_PATH_MISSING = "vault path missing"
    SUBAGENT_FAILURE = "subagent crash or timeout"
    CONFIGURATION_INVALID = "invalid configuration"
    LIVE_LIMIT = "live verification limit"
    INTERNAL = "internal error"


# Exit codes are stable so scripts and tests can rely on them.
EXIT_CODES = {
    Failure.MISSING_PREREQUISITE: 10,
    Failure.PERMISSION_DECLINED: 11,
    Failure.UNSUPPORTED_PLATFORM: 12,
    Failure.PIN_MISMATCH: 13,
    Failure.PROVIDER_UNAVAILABLE: 14,
    Failure.CREDENTIALS_NOT_CONFIGURED: 15,
    Failure.AUTHORIZATION_EXPIRED: 16,
    Failure.REFRESH_CONFLICT: 17,
    Failure.EXTERNAL_SERVICE_UNAVAILABLE: 18,
    Failure.MODEL_NOT_IN_CATALOG: 19,
    Failure.SEARCH_UNSUPPORTED: 20,
    Failure.NETWORK_POLICY_BLOCKED: 21,
    Failure.OBSIDIAN_NOT_CONFIGURED: 22,
    Failure.VAULT_PATH_MISSING: 23,
    Failure.SUBAGENT_FAILURE: 24,
    Failure.CONFIGURATION_INVALID: 25,
    Failure.LIVE_LIMIT: 26,
    Failure.INTERNAL: 70,
}


class StudyRoomError(Exception):
    """A classified, already-redacted failure."""

    def __init__(self, failure: Failure, message: str, *, hint: str | None = None):
        self.failure = failure
        self.message = redact.redact_text(message)
        self.hint = redact.redact_text(hint) if hint else None
        super().__init__(self.render())

    @property
    def exit_code(self) -> int:
        return EXIT_CODES[self.failure]

    def render(self) -> str:
        text = f"study-room: {self.failure.value}: {self.message}"
        if self.hint:
            text += f"\n  hint: {self.hint}"
        return text


def fail(failure: Failure, message: str, *, hint: str | None = None) -> StudyRoomError:
    return StudyRoomError(failure, message, hint=hint)
