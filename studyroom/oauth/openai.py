"""OpenAI "Sign in with ChatGPT" for the pinned Pi `openai` provider (SPEC 15.4).

Mirrors the public-client flow pi-ai 1.0.x implements for its `openai`
provider (auth/oauth/openai-chatgpt.js): PKCE with a dynamically issued
client, an installation ("agent host") identifier, the
``chatgpt.tokens.use.direct`` scope, and refresh with the issued client ID.
The resulting access token authenticates requests to api.openai.com/v1;
the sandbox sees only a placeholder that the Docker Sandboxes proxy swaps
for it.

The flow runs entirely in this trusted host process. Tokens never appear in
arguments, files, or output.
"""

from __future__ import annotations

import base64
import hashlib
import http.server
import secrets
import threading
import time
import urllib.parse
import uuid
from dataclasses import dataclass
from typing import Callable

from .. import redact
from ..errors import Failure, fail
from ..http import Client
from .state import OAuthState

AUTHORIZE_URL = "https://auth.openai.com/api/accounts/authorize"
TOKEN_URL = "https://auth.openai.com/api/accounts/oauth/token"
MODELS_URL = "https://api.openai.com/v1/models"
RESOURCE = "https://api.openai.com/v1"
DYNAMIC_CLIENT_ID = "dynamic_agent_client"
AGENT_NAME_HINT = "Pi"
CALLBACK_HOST = "127.0.0.1"
CALLBACK_PORT = 1455
CALLBACK_PATH = "/auth/callback"
REDIRECT_URI = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}{CALLBACK_PATH}"
DIRECT_TOKEN_SCOPE = "chatgpt.tokens.use.direct"
SCOPE = f"openid profile email offline_access resource.invoke {DIRECT_TOKEN_SCOPE}"
# Same margin pi-ai applies, so a request never starts with a nearly expired token.
EXPIRY_MARGIN_MS = 3 * 60 * 1000


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


@dataclass
class Pkce:
    verifier: str
    challenge: str

    @classmethod
    def new(cls) -> "Pkce":
        verifier = _b64url(secrets.token_bytes(32))
        challenge = _b64url(hashlib.sha256(verifier.encode()).digest())
        return cls(verifier, challenge)


def agent_host_id(installation_id: str) -> str:
    try:
        return f"urn:uuid:{uuid.UUID(installation_id)}"
    except ValueError:
        raise fail(Failure.CONFIGURATION_INVALID, "the installation ID is not a UUID") from None


def authorization_url(installation_id: str, pkce: Pkce, state: str, nonce: str) -> str:
    query = {
        "client_id": DYNAMIC_CLIENT_ID,
        "agent_name_hint": AGENT_NAME_HINT,
        "ext_agent_host_id": agent_host_id(installation_id),
        "response_type": "code",
        "redirect_uri": REDIRECT_URI,
        "resource": RESOURCE,
        "scope": SCOPE,
        "state": state,
        "code_challenge": pkce.challenge,
        "code_challenge_method": "S256",
        "nonce": nonce,
    }
    return f"{AUTHORIZE_URL}?{urllib.parse.urlencode(query)}"


def parse_callback(url: str, expected_state: str) -> tuple[str, str]:
    """Return (code, issued client_id) from the redirect URL."""
    parts = urllib.parse.urlsplit(url.strip())
    if f"{parts.scheme}://{parts.netloc}{parts.path}" != REDIRECT_URI:
        raise fail(Failure.PERMISSION_DECLINED, f"the callback URL must start with {REDIRECT_URI}")
    q = urllib.parse.parse_qs(parts.query)
    if "error" in q:
        raise fail(Failure.PERMISSION_DECLINED, f"ChatGPT authorization failed: {q['error'][0]}")
    state = (q.get("state") or [""])[0]
    if not state or not secrets.compare_digest(state, expected_state):
        raise fail(Failure.PERMISSION_DECLINED, "OAuth state mismatch; start `study-room auth openai` again")
    code = (q.get("code") or [""])[0]
    client_id = (q.get("client_id") or [""])[0].strip()
    if not code:
        raise fail(Failure.PERMISSION_DECLINED, "the callback carried no authorization code")
    if not client_id:
        raise fail(Failure.PROVIDER_UNAVAILABLE, "OpenAI did not return an issued client ID in the callback")
    redact.register(code)
    return code, client_id


def _token_request(client: Client, form: dict[str, str]) -> dict:
    resp = client.request("POST", TOKEN_URL, form=form)
    if resp.status in (400, 401, 403):
        body = resp.json() if isinstance(resp.json(), dict) else {}
        err = str(body.get("error", "")) if isinstance(body, dict) else ""
        if err in ("invalid_grant", "invalid_client", "unauthorized_client") or resp.status in (401, 403):
            raise fail(
                Failure.AUTHORIZATION_EXPIRED,
                f"OpenAI rejected the authorization ({resp.status} {err or 'unauthorized'})",
                hint="run `study-room auth openai` to authorize this host again",
            )
    if not resp.ok:
        raise fail(Failure.PROVIDER_UNAVAILABLE, f"OpenAI token endpoint answered {resp.status}: {redact.redact_text(resp.text()[:300])}")
    data = resp.json()
    if not isinstance(data, dict):
        raise fail(Failure.PROVIDER_UNAVAILABLE, "OpenAI token response was not a JSON object")
    redact.register_mapping(data)
    return data


def _credential(data: dict, now_ms: int) -> tuple[str, str, int, list[str]]:
    access, refresh, scope = data.get("access_token"), data.get("refresh_token"), data.get("scope")
    expires_in = data.get("expires_in")
    if not isinstance(access, str) or not access or not isinstance(refresh, str) or not refresh:
        raise fail(Failure.PROVIDER_UNAVAILABLE, "OpenAI token response lacks an access or refresh token")
    if not isinstance(scope, str) or DIRECT_TOKEN_SCOPE not in scope.split():
        raise fail(Failure.PROVIDER_UNAVAILABLE, f"OpenAI grant did not include {DIRECT_TOKEN_SCOPE}")
    if not isinstance(expires_in, (int, float)) or expires_in <= 0:
        raise fail(Failure.PROVIDER_UNAVAILABLE, "OpenAI token response has an invalid expires_in")
    return access, refresh, int(now_ms + expires_in * 1000 - EXPIRY_MARGIN_MS), scope.split()


def exchange(client: Client, code: str, pkce: Pkce, client_id: str, installation_id: str, now_ms: int | None = None) -> OAuthState:
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    data = _token_request(
        client,
        {
            "grant_type": "authorization_code",
            "client_id": client_id,
            "code": code,
            "code_verifier": pkce.verifier,
            "redirect_uri": REDIRECT_URI,
            "resource": RESOURCE,
        },
    )
    if not isinstance(data.get("id_token"), str) or not data["id_token"]:
        raise fail(Failure.PROVIDER_UNAVAILABLE, "OpenAI token response did not contain an ID token")
    access, refresh, expires_ms, scopes = _credential(data, now_ms)
    return OAuthState(
        provider="openai",
        installation_id=installation_id,
        access=access,
        refresh=refresh,
        expires_ms=expires_ms,
        client_id=client_id,
        scopes=scopes,
        account={"agent_host_id": agent_host_id(installation_id)},
        obtained_at_ms=now_ms,
        rotated_at_ms=now_ms,
    )


def refresh(client: Client, state: OAuthState, now_ms: int | None = None) -> OAuthState:
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    if not state.client_id:
        raise fail(Failure.AUTHORIZATION_EXPIRED, "stored OpenAI state has no issued client ID", hint="run `study-room auth openai`")
    data = _token_request(
        client,
        {"grant_type": "refresh_token", "client_id": state.client_id, "refresh_token": state.refresh, "resource": RESOURCE},
    )
    access, new_refresh, expires_ms, scopes = _credential(data, now_ms)
    return state.rotated(access, new_refresh, expires_ms, now_ms, scopes=scopes)


def list_models(client: Client, access: str) -> list[str]:
    """Model IDs visible to this authorization (the authenticated catalog, SPEC 14.2)."""
    redact.register(access)
    resp = client.request("GET", MODELS_URL, headers={"Authorization": f"Bearer {access}"})
    if resp.status in (401, 403):
        raise fail(Failure.AUTHORIZATION_EXPIRED, f"OpenAI refused the catalog request ({resp.status})")
    if not resp.ok:
        raise fail(Failure.PROVIDER_UNAVAILABLE, f"OpenAI catalog request answered {resp.status}")
    data = resp.json()
    items = data.get("data", []) if isinstance(data, dict) else []
    return sorted(str(m.get("id")) for m in items if isinstance(m, dict) and m.get("id"))


# ── Interactive login ─────────────────────────────────────────────────────


class _CallbackServer(http.server.HTTPServer):
    result: str | None = None


def _start_callback_server() -> _CallbackServer | None:
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if urllib.parse.urlsplit(self.path).path != CALLBACK_PATH:
                self.send_response(404)
                self.end_headers()
                return
            self.server.result = f"http://{CALLBACK_HOST}:{CALLBACK_PORT}{self.path}"  # type: ignore[attr-defined]
            body = b"<html><body><p>Study Room: ChatGPT sign-in received. You can close this window.</p></body></html>"
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):  # silence: URLs carry the authorization code
            return

    try:
        return _CallbackServer((CALLBACK_HOST, CALLBACK_PORT), Handler)
    except OSError:
        return None


def login(
    client: Client,
    installation_id: str,
    *,
    say: Callable[[str], None],
    open_browser: Callable[[str], None],
    ask: Callable[[str], str],
    timeout_s: float = 600,
) -> OAuthState:
    """Interactive ceremony; never bypassed by --yes (SPEC 16.1)."""
    pkce = Pkce.new()
    state = _b64url(secrets.token_bytes(32))
    nonce = _b64url(secrets.token_bytes(32))
    url = authorization_url(installation_id, pkce, state, nonce)
    server = _start_callback_server()
    say("Sign in with ChatGPT in your browser. Study Room stores the result in Infisical for this host only.")
    say(f"If no browser opens, visit:\n  {url}")
    open_browser(url)
    callback: str | None = None
    if server is not None:
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        deadline = time.monotonic() + timeout_s
        say(f"Waiting for the browser to return to {REDIRECT_URI} (or press Ctrl+C and rerun to paste the URL)...")
        try:
            while time.monotonic() < deadline and server.result is None:
                time.sleep(0.2)
        finally:
            server.shutdown()
            server.server_close()
        callback = server.result
    if callback is None:
        callback = ask(f"Paste the final redirect URL (it starts with {REDIRECT_URI}): ")
    code, client_id = parse_callback(callback, state)
    return exchange(client, code, pkce, client_id, installation_id)
