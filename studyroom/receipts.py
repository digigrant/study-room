"""Non-secret verification receipts (SPEC 20.4).

A receipt records when live checks ran, for which installation, against which
configuration and pin fingerprints, provider and verification model, vault
identity, and which checks passed, were skipped, or failed. Entry warns when
connectivity was never checked or a relevant fingerprint changed. Receipts
never claim anything about the runtime model's teaching quality.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

from . import fsutil
from .config import Config
from .lock import Lock


def config_fingerprint(config: Config) -> str:
    relevant = {
        "profiles": config.data["profiles"],
        "providers": config.data["providers"],
        "network": config.data["network"],
        "sandbox": config.data["sandbox"],
    }
    return hashlib.sha256(json.dumps(relevant, sort_keys=True).encode()).hexdigest()


def vault_identity(config: Config) -> str:
    """A hash, so receipts do not record the vault path itself."""
    return hashlib.sha256(f"{config.vault_path}\0{config.data['vault']['study_dir']}".encode()).hexdigest()[:16]


def write(config: Config, lock: Lock, provider: str, model: str, checks: dict[str, str], *, now: float | None = None) -> Path:
    now = time.time() if now is None else now
    receipt = {
        "time": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
        "installation_id": config.installation_id,
        "config_fingerprint": config_fingerprint(config),
        "lock_fingerprint": lock.fingerprint,
        "provider": provider,
        "verification_model": model,
        "vault_identity": vault_identity(config),
        "checks": checks,
        "note": "Live checks prove connectivity and plumbing only, not teaching or research quality.",
    }
    path = config.paths.receipts_dir / f"{time.strftime('%Y%m%dT%H%M%S', time.gmtime(now))}-{provider}.json"
    fsutil.atomic_write_json(path, receipt)
    fsutil.atomic_write_json(config.paths.receipts_dir / f"latest-{provider}.json", receipt)
    return path


def latest(config: Config, provider: str) -> dict | None:
    data = fsutil.read_json(config.paths.receipts_dir / f"latest-{provider}.json")
    return data if isinstance(data, dict) else None


def warnings(config: Config, lock: Lock, provider: str) -> list[str]:
    r = latest(config, provider)
    if r is None:
        return [f"{provider} connectivity has never been verified on this host (`study-room verify --live {provider}`)"]
    out = []
    if r.get("lock_fingerprint") != lock.fingerprint:
        out.append(f"pins changed since the last {provider} live check ({r.get('time')}); re-run `study-room verify --live`")
    if r.get("config_fingerprint") != config_fingerprint(config):
        out.append(f"model or network configuration changed since the last {provider} live check")
    failed = [k for k, v in (r.get("checks") or {}).items() if v == "failed"]
    if failed:
        out.append(f"the last {provider} live check failed: {', '.join(failed)}")
    return out


def verified(config: Config, lock: Lock, provider: str) -> bool:
    r = latest(config, provider)
    return bool(r) and not warnings(config, lock, provider) and "passed" in (r.get("checks") or {}).values()
