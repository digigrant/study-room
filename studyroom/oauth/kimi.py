"""Kimi Code device authorization for the pinned Pi `kimi-coding` provider (SPEC 15.5).

A trusted wrapper around the RFC 8628 device flow pi-ai 1.0.x uses
(auth/oauth/kimi-coding.js): device authorization at auth.kimi.com, token
polling, and refresh with rotation. The access token authenticates requests
to https://api.kimi.com/coding. Kimi stays experimental until its live
capability gate passes; nothing here enables it.
"""

from __future__ import annotations

import time
from typing import Callable

from .. import redact
from ..errors import Failure, fail
from ..http import Client
from .state import OAuthState

OAUTH_HOST = "https://auth.kimi.com"
CLIENT_ID = "17e5f671-d194-4dfb-9706-5516cb48c098"
DEVICE_URL = f"{OAUTH_HOST}/api/oauth/device_authorization"
TOKEN_URL = f"{OAUTH_HOST}/api/oauth/token"
MODELS_URL = "https://api.kimi.com/coding/v1/models"
DEFAULT_INTERVAL = 5


def _parse_token(data: dict, now_ms: int) -> tuple[str, str, int]:
    access, refresh, expires_in = data.get("access_token"), data.get("refresh_token"), data.get("expires_in")
    if not isinstance(access, str) or not access or not isinstance(refresh, str) or not refresh:
        raise fail(Failure.PROVIDER_UNAVAILABLE, "Kimi token response lacks an access or refresh token")
    if not isinstance(expires_in, (int, float)) or expires_in <= 0:
        raise fail(Failure.PROVIDER_UNAVAILABLE, "Kimi token response has an invalid expires_in")
    redact.register(access)
    redact.register(refresh)
    return access, refresh, int(now_ms + expires_in * 1000)


def start_device(client: Client) -> dict:
    resp = client.request("POST", DEVICE_URL, form={"client_id": CLIENT_ID})
    data = resp.json()
    if not resp.ok or not isinstance(data, dict):
        raise fail(Failure.PROVIDER_UNAVAILABLE, f"Kimi device authorization answered {resp.status}")
    for key in ("device_code", "user_code", "verification_uri", "verification_uri_complete"):
        if not isinstance(data.get(key), str) or not data[key]:
            raise fail(Failure.PROVIDER_UNAVAILABLE, f"Kimi device authorization response lacks {key}")
    if not str(data["verification_uri_complete"]).startswith("https://"):
        raise fail(Failure.PROVIDER_UNAVAILABLE, "Kimi returned a non-HTTPS verification URL")
    redact.register(data["device_code"])
    return data


def poll(client: Client, device: dict, installation_id: str, *, sleep: Callable[[float], None] = time.sleep, now: Callable[[], float] = time.time) -> OAuthState:
    interval = device.get("interval") if isinstance(device.get("interval"), (int, float)) and device["interval"] > 0 else DEFAULT_INTERVAL
    expires_in = device.get("expires_in") if isinstance(device.get("expires_in"), (int, float)) else 900
    deadline = now() + expires_in
    while now() < deadline:
        sleep(interval)
        resp = client.request(
            "POST",
            TOKEN_URL,
            form={"client_id": CLIENT_ID, "device_code": device["device_code"], "grant_type": "urn:ietf:params:oauth:grant-type:device_code"},
        )
        data = resp.json() if isinstance(resp.json(), dict) else {}
        if resp.ok and isinstance(data.get("access_token"), str):
            now_ms = int(now() * 1000)
            access, refresh, expires_ms = _parse_token(data, now_ms)
            return OAuthState("kimi", installation_id, access, refresh, expires_ms, obtained_at_ms=now_ms, rotated_at_ms=now_ms)
        if resp.status >= 500:
            raise fail(Failure.PROVIDER_UNAVAILABLE, f"Kimi token endpoint answered {resp.status}")
        error = data.get("error")
        if error == "authorization_pending":
            continue
        if error == "slow_down":
            interval = data.get("interval") if isinstance(data.get("interval"), (int, float)) else interval + 5
            continue
        if error == "access_denied":
            raise fail(Failure.PERMISSION_DECLINED, "Kimi sign-in was denied")
        if error == "expired_token":
            break
        raise fail(Failure.PROVIDER_UNAVAILABLE, f"Kimi device token request failed ({resp.status} {error or ''})")
    raise fail(Failure.AUTHORIZATION_EXPIRED, "Kimi device authorization expired before it was approved")


def refresh(client: Client, state: OAuthState, now_ms: int | None = None) -> OAuthState:
    now_ms = int(time.time() * 1000) if now_ms is None else now_ms
    resp = client.request("POST", TOKEN_URL, form={"client_id": CLIENT_ID, "grant_type": "refresh_token", "refresh_token": state.refresh})
    data = resp.json() if isinstance(resp.json(), dict) else {}
    if resp.status in (401, 403) or data.get("error") == "invalid_grant":
        raise fail(Failure.AUTHORIZATION_EXPIRED, f"Kimi rejected the refresh ({resp.status})", hint="run `study-room auth kimi`")
    if not resp.ok:
        raise fail(Failure.PROVIDER_UNAVAILABLE, f"Kimi token endpoint answered {resp.status}")
    access, new_refresh, expires_ms = _parse_token(data, now_ms)
    return state.rotated(access, new_refresh, expires_ms, now_ms)


def login(client: Client, installation_id: str, *, say: Callable[[str], None], open_browser: Callable[[str], None]) -> OAuthState:
    device = start_device(client)
    say("Kimi Code is EXPERIMENTAL in Study Room until its live capability checks pass.")
    say(f"Approve this device in your browser: {device['verification_uri_complete']}")
    say(f"Code: {device['user_code']}")
    open_browser(device["verification_uri_complete"])
    return poll(client, device, installation_id)


def list_models(client: Client, access: str) -> list[str]:
    """UNVERIFIED endpoint: Kimi's coding catalog. Used only by explicit `study-room models kimi`."""
    redact.register(access)
    resp = client.request("GET", MODELS_URL, headers={"Authorization": f"Bearer {access}"})
    if resp.status in (401, 403):
        raise fail(Failure.AUTHORIZATION_EXPIRED, f"Kimi refused the catalog request ({resp.status})")
    if not resp.ok:
        raise fail(Failure.PROVIDER_UNAVAILABLE, f"Kimi catalog request answered {resp.status}")
    data = resp.json()
    items = data.get("data", []) if isinstance(data, dict) else []
    return sorted(str(m.get("id")) for m in items if isinstance(m, dict) and m.get("id"))
