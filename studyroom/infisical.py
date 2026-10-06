"""Infisical access with the ``sbx-host`` machine identity (SPEC 15.2).

* Credentials (project ID, client ID, client secret) come from Study Room's
  own keyring namespace; they are sent only in request bodies over HTTPS.
* Every operation logs in fresh with Universal Auth and discards the access
  token afterwards; nothing is cached on disk.
* Study Room writes only below its own namespace,
  ``/study-room/oauth/<provider>/<installation-id>``. The client refuses any
  other write path, so even a broader grant on the identity is never used
  for other paths. Whether Infisical enforces that scope server-side is a
  separate, host-side permission question (SPEC 26).
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass

from . import redact
from .errors import Failure, fail
from .http import Client
from .keyring import Keyring

_SEGMENT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


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


def oauth_path(prefix: str, provider: str, installation_id: str) -> str:
    for part in (provider, installation_id):
        if not _SEGMENT.match(part):
            raise fail(Failure.CONFIGURATION_INVALID, f"invalid Infisical path segment {part!r}")
    prefix = "/" + prefix.strip("/")
    return f"{prefix}/{provider}/{installation_id}"


class Infisical:
    def __init__(self, domain: str, environment: str, handles: Handles, client: Client | None = None, *, write_prefix: str = "/study-room/oauth"):
        if not domain.startswith("https://"):
            raise fail(Failure.CONFIGURATION_INVALID, "the Infisical domain must be an https:// URL")
        self.domain = domain.rstrip("/")
        self.environment = environment
        self.handles = handles
        self.client = client or Client(timeout=20)
        self.write_prefix = "/" + write_prefix.strip("/")
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

    def _check_write_path(self, path: str) -> None:
        if not (path == self.write_prefix or path.startswith(self.write_prefix + "/")):
            raise fail(Failure.CONFIGURATION_INVALID, f"refusing to write outside {self.write_prefix}: {path}")

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
            raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, f"the sbx-host identity may not read {path}/{name} ({resp.status})")
        if not resp.ok:
            raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, f"Infisical read answered {resp.status}")
        data = resp.json()
        value = data.get("secret", {}).get("secretValue") if isinstance(data, dict) else None
        if not isinstance(value, str):
            raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, "Infisical read response had no secret value")
        redact.register(value)
        return value

    def ensure_folders(self, path: str, *, token: str) -> None:
        """Create ``path`` (inside the write prefix); missing parents are created by the same call.

        Infisical checks the permission against the parent path, so an identity
        scoped to the prefix can create the provider and installation folders
        once an administrator has created the prefix itself.
        """
        self._check_write_path(path)
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
            raise fail(
                Failure.CREDENTIALS_NOT_CONFIGURED,
                f"the sbx-host identity may not create {path} ({resp.status})",
                hint=f"an Infisical administrator must create {self.write_prefix} and grant sbx-host access to it (docs/SETUP.md)",
            )
        if resp.status == 404:
            raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, f"Infisical environment {self.environment!r} or a parent of {path} does not exist")
        raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, f"Infisical folder creation answered {resp.status}")

    def revoke(self, token: str) -> None:
        """Best effort: end the short-lived session instead of letting it idle until expiry."""
        try:
            self.client.request("POST", f"{self.domain}/api/v1/auth/token/revoke", json_body={"accessToken": token})
        except Exception:  # noqa: BLE001 - revocation failure never fails the caller
            pass

    def put(self, path: str, name: str, value: str, *, exists: bool, token: str | None = None) -> None:
        """Create or replace one secret value in a single request (atomic per value)."""
        self._check_write_path(path)
        token = token or self._token()
        redact.register(value)
        body = {"projectId": self.handles.project_id, "environment": self.environment, "secretPath": path, "secretValue": value, "type": "shared"}
        url = f"{self.domain}/api/v4/secrets/{urllib.parse.quote(name, safe='')}"
        resp = self.client.request("PATCH" if exists else "POST", url, json_body=body, headers=self._auth(token))
        if not exists and resp.status == 404:
            # Create does not make folders: add the path, then retry once.
            self.ensure_folders(path, token=token)
            resp = self.client.request("POST", url, json_body=body, headers=self._auth(token))
        if not exists and resp.status == 400 and "already exists" in resp.text().lower():
            resp = self.client.request("PATCH", url, json_body=body, headers=self._auth(token))
        if resp.status in (401, 403):
            raise fail(
                Failure.CREDENTIALS_NOT_CONFIGURED,
                f"the sbx-host identity may not write {path} ({resp.status})",
                hint="grant sbx-host read/write on the Study Room path only (docs/SETUP.md, Infisical)",
            )
        if resp.status == 429:
            raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, "Infisical rate-limited the write (429)")
        if not resp.ok:
            raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, f"Infisical write answered {resp.status}")
        data = resp.json()
        if isinstance(data, dict) and "approval" in data and "secret" not in data:
            raise fail(
                Failure.CONFIGURATION_INVALID,
                f"Infisical queued the write to {path} for change approval instead of applying it",
                hint="exclude the Study Room path from change-approval policies; rotated credentials must be written immediately",
            )

    def session_token(self) -> str:
        return self._token()


@dataclass
class FakeInfisical:
    """In-memory stand-in with the same interface, for hermetic tests."""

    values: dict[tuple[str, str], str]
    reads: int = 0
    writes: int = 0
    fail_writes: int = 0
    write_prefix: str = "/study-room/oauth"

    def session_token(self) -> str:
        return "fake-infisical-session"

    def revoke(self, token: str) -> None:
        self.revoked = getattr(self, "revoked", 0) + 1

    def get(self, path: str, name: str, *, token: str | None = None) -> str | None:
        self.reads += 1
        return self.values.get((path, name))

    def put(self, path: str, name: str, value: str, *, exists: bool, token: str | None = None) -> None:
        if not path.startswith(self.write_prefix):
            raise fail(Failure.CONFIGURATION_INVALID, f"refusing to write outside {self.write_prefix}: {path}")
        if self.fail_writes:
            self.fail_writes -= 1
            raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, "fake Infisical write failure")
        self.writes += 1
        self.values[(path, name)] = value
