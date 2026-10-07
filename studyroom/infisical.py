"""Infisical access with the ``sbx-host`` machine identity (SPEC 15.2).

* Credentials (project ID, client ID, client secret) come from Study Room's
  own keyring namespace; they are sent only in request bodies over HTTPS.
* Every operation logs in fresh with Universal Auth and revokes the session
  token afterwards; nothing is cached on disk.
* Study Room writes only the provider OAuth secrets named in its
  configuration. By the captain's decision of 2026-10-06 these live in the
  existing Agents project (``OPENAI_REFRESH_TOKEN``, created by the captain;
  ``KIMI_REFRESH_TOKEN`` for Kimi). The client refuses every other write, so
  the identity's project-wide grant is never used for anything else.
"""

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field

from . import redact
from .errors import Failure, fail
from .http import Client
from .keyring import Keyring


@dataclass(frozen=True)
class Handles:
    project_id: str
    client_id: str
    client_secret: str


def handles_from_keyring(keyring: Keyring, *, interactive: bool = False) -> Handles:
    return Handles(
        project_id=keyring.lookup("infisical-project-id", interactive=interactive),
        client_id=keyring.lookup("infisical-client-id", interactive=interactive),
        client_secret=keyring.lookup("infisical-client-secret", interactive=interactive),
    )


class Infisical:
    def __init__(
        self,
        domain: str,
        environment: str,
        handles: Handles,
        client: Client | None = None,
        *,
        writable: set[tuple[str, str]] | frozenset[tuple[str, str]] = frozenset(),
    ):
        if not domain.startswith("https://"):
            raise fail(Failure.CONFIGURATION_INVALID, "the Infisical domain must be an https:// URL")
        self.domain = domain.rstrip("/")
        self.environment = environment
        self.handles = handles
        self.client = client or Client(timeout=20)
        self.writable = frozenset(writable)
        redact.register(handles.client_secret)
        redact.register(handles.client_id)
        redact.register(handles.project_id)

    # --- auth ------------------------------------------------------------
    def _token(self) -> str:
        resp = self.client.request(
            "POST",
            f"{self.domain}/api/v1/auth/universal-auth/login",
            json_body={"clientId": self.handles.client_id, "clientSecret": self.handles.client_secret},
        )
        if resp.status in (400, 401, 403):
            raise fail(
                Failure.CREDENTIALS_NOT_CONFIGURED,
                f"Infisical rejected the sbx-host login ({resp.status})",
                hint="check the client secret stored by `study-room setup`; repeated failures lock the identity for a few minutes",
            )
        if resp.status == 429:
            raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, "Infisical rate-limited the login (429)")
        if not resp.ok:
            raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, f"Infisical login answered {resp.status}")
        data = resp.json()
        token = data.get("accessToken") if isinstance(data, dict) else None
        if not isinstance(token, str) or not token:
            raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, "Infisical login response had no access token")
        redact.register(token)
        return token

    def _auth(self, token: str) -> dict[str, str]:
        return {"Authorization": f"Bearer {token}"}

    def _check_write(self, path: str, name: str) -> None:
        if (path, name) not in self.writable:
            raise fail(Failure.CONFIGURATION_INVALID, f"refusing to write {path.rstrip('/')}/{name}: Study Room writes only its configured OAuth secrets")

    # --- secrets ---------------------------------------------------------
    def get(self, path: str, name: str, *, token: str | None = None) -> str | None:
        token = token or self._token()
        query = urllib.parse.urlencode(
            {
                "projectId": self.handles.project_id,
                "environment": self.environment,
                "secretPath": path,
                "viewSecretValue": "true",
                "expandSecretReferences": "false",
                "includeImports": "false",
            }
        )
        resp = self.client.request("GET", f"{self.domain}/api/v4/secrets/{urllib.parse.quote(name, safe='')}?{query}", headers=self._auth(token))
        if resp.status == 404:
            return None
        if resp.status in (401, 403):
            raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, f"the sbx-host identity may not read {path.rstrip('/')}/{name} ({resp.status})")
        if not resp.ok:
            raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, f"Infisical read answered {resp.status}")
        data = resp.json()
        value = data.get("secret", {}).get("secretValue") if isinstance(data, dict) else None
        if not isinstance(value, str):
            raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, "Infisical read response had no secret value")
        redact.register(value)
        return value

    def ensure_folder(self, path: str, *, token: str) -> None:
        """Create ``path`` and any missing parents (one call). The root always exists."""
        if path == "/":
            return
        parent, _, name = path.rstrip("/").rpartition("/")
        resp = self.client.request(
            "POST",
            f"{self.domain}/api/v2/folders",
            json_body={"projectId": self.handles.project_id, "environment": self.environment, "name": name, "path": parent or "/"},
            headers=self._auth(token),
        )
        if resp.ok or (resp.status == 400 and "already exists" in resp.text().lower()):
            return
        if resp.status in (401, 403):
            raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, f"the sbx-host identity may not create the folder {path} ({resp.status})")
        if resp.status == 404:
            raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, f"Infisical environment {self.environment!r} does not exist")
        raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, f"Infisical folder creation answered {resp.status}")

    def revoke(self, token: str) -> None:
        """Best effort: end the short-lived session instead of letting it idle until expiry."""
        try:
            self.client.request("POST", f"{self.domain}/api/v1/auth/token/revoke", json_body={"accessToken": token})
        except Exception:  # noqa: BLE001 - revocation failure never fails the caller
            pass

    def put(self, path: str, name: str, value: str, *, exists: bool, token: str | None = None) -> None:
        """Create or replace one secret value in a single request (atomic per value)."""
        self._check_write(path, name)
        token = token or self._token()
        redact.register(value)
        body = {"projectId": self.handles.project_id, "environment": self.environment, "secretPath": path, "secretValue": value, "type": "shared"}
        url = f"{self.domain}/api/v4/secrets/{urllib.parse.quote(name, safe='')}"
        resp = self.client.request("PATCH" if exists else "POST", url, json_body=body, headers=self._auth(token))
        if not exists and resp.status == 404:
            # Create does not make folders: add the path, then retry once.
            self.ensure_folder(path, token=token)
            resp = self.client.request("POST", url, json_body=body, headers=self._auth(token))
        if not exists and resp.status == 400 and "already exists" in resp.text().lower():
            resp = self.client.request("PATCH", url, json_body=body, headers=self._auth(token))
        if exists and resp.status == 404:
            resp = self.client.request("POST", url, json_body=body, headers=self._auth(token))
        if resp.status in (401, 403):
            raise fail(
                Failure.CREDENTIALS_NOT_CONFIGURED,
                f"the sbx-host identity may not write {path.rstrip('/')}/{name} ({resp.status})",
                hint="sbx-host needs write access to the OAuth secret in the Agents project (docs/SETUP.md, Infisical)",
            )
        if resp.status == 429:
            raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, "Infisical rate-limited the write (429)")
        if not resp.ok:
            raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, f"Infisical write answered {resp.status}")
        data = resp.json()
        if isinstance(data, dict) and "approval" in data and "secret" not in data:
            raise fail(
                Failure.CONFIGURATION_INVALID,
                f"Infisical queued the write to {name} for change approval instead of applying it",
                hint="exclude the OAuth secret from change-approval policies; rotated credentials must be written immediately",
            )

    def session_token(self) -> str:
        return self._token()


@dataclass
class FakeInfisical:
    """In-memory stand-in with the same interface, for hermetic tests."""

    values: dict[tuple[str, str], str]
    writable: set[tuple[str, str]] = field(default_factory=lambda: {("/", "OPENAI_REFRESH_TOKEN"), ("/", "KIMI_REFRESH_TOKEN")})
    reads: int = 0
    writes: int = 0
    fail_writes: int = 0
    revoked: int = 0

    def session_token(self) -> str:
        return "fake-infisical-session"

    def revoke(self, token: str) -> None:
        self.revoked += 1

    def get(self, path: str, name: str, *, token: str | None = None) -> str | None:
        self.reads += 1
        return self.values.get((path, name))

    def put(self, path: str, name: str, value: str, *, exists: bool, token: str | None = None) -> None:
        if (path, name) not in self.writable:
            raise fail(Failure.CONFIGURATION_INVALID, f"refusing to write {path}/{name}")
        if self.fail_writes:
            self.fail_writes -= 1
            raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, "fake Infisical write failure")
        self.writes += 1
        self.values[(path, name)] = value
