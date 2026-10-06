"""Trusted host configuration (SPEC 8.2, 13.2, 14.2, 15.3).

Stored at ``~/.config/study-room/config.json`` with owner-only permissions.
It holds only non-secret settings: the vault location, the network mode, the
runtime model profiles, and the installation ID. Credentials never appear
here; the keyring holds the Infisical handles and Infisical holds provider
state.
"""

from __future__ import annotations

import copy
import re
import uuid
from pathlib import Path

from . import fsutil
from .errors import Failure, fail
from .paths import HostPaths

SCHEMA = 1

THINKING_LEVELS = ("off", "minimal", "low", "medium", "high", "xhigh", "max")
PROVIDERS = ("openai", "kimi")
NETWORK_MODES = ("balanced", "web")

# Pi provider IDs for Study Room's provider names. OpenAI uses Pi's `openai`
# provider (Responses API at api.openai.com) with a ChatGPT sign-in token;
# Kimi uses Pi's `kimi-coding` provider (api.kimi.com/coding).
PI_PROVIDER_IDS = {"openai": "openai", "kimi": "kimi-coding"}

DEFAULTS: dict = {
    "schema": SCHEMA,
    "installation_id": None,
    "vault": {
        "path": None,  # filled from XDG data dir on first write
        "study_dir": "Study Room",
    },
    "sandbox": {
        "name": "study-room",
    },
    "network": {
        "mode": "balanced",
    },
    "profiles": {
        # Production model IDs are pinned only after the authenticated catalog
        # has been inspected (SPEC 14.2); until then they are unset and entry
        # refuses to start a teaching session.
        "main": {"provider": "openai", "model": None, "thinking": "max", "thinking_fallback": None},
        "researcher": {
            "provider": None,  # None: follow main.provider/model at initialization
            "model": None,
            "thinking": "medium",
            "allowed_model_overrides": [],
        },
        "search": {"provider": "openai", "model": None},
    },
    "providers": {
        "openai": {"enabled": True},
        # Kimi ships capability-gated: disabled and experimental until its
        # live checks pass (SPEC 14.1, 15.5).
        "kimi": {"enabled": False, "experimental": True},
    },
    "infisical": {
        "domain": "https://app.infisical.com",
        "environment": "dev",
        # Captain's decision (2026-10-06): provider OAuth state is kept in the
        # existing Agents project, in the secret the captain created for it.
        # One value per provider holds an entry per installation ID.
        "oauth_secrets": {
            "openai": {"path": "/", "name": "OPENAI_REFRESH_TOKEN"},
            "kimi": {"path": "/", "name": "KIMI_REFRESH_TOKEN"},
        },
        "github_secret_path": "/",
        "github_secret_name": "GITHUB_GEJ_MACHINE_PAT",
    },
    "github": {
        "enabled": True,
    },
    "updates": {
        "interval_hours": 24,
    },
    "secrets": {
        # How often Docker Sandboxes re-runs the host resolver for a value.
        "refresh": "5m",
        "github_refresh": "55m",
    },
}


def _merge(base: dict, override: dict) -> dict:
    out = copy.deepcopy(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _merge(out[key], value)
        else:
            out[key] = copy.deepcopy(value)
    return out


class Config:
    def __init__(self, data: dict, paths: HostPaths):
        self.data = data
        self.paths = paths

    # --- accessors -------------------------------------------------------
    @property
    def installation_id(self) -> str:
        value = self.data.get("installation_id")
        if not value:
            raise fail(Failure.CONFIGURATION_INVALID, "no installation ID; run `study-room setup` first")
        return value

    @property
    def vault_path(self) -> Path:
        return Path(self.data["vault"]["path"]).expanduser()

    @property
    def study_dir(self) -> Path:
        return self.vault_path / self.data["vault"]["study_dir"]

    @property
    def sandbox_name(self) -> str:
        return self.data["sandbox"]["name"]

    @property
    def network_mode(self) -> str:
        return self.data["network"]["mode"]

    def profile(self, name: str) -> dict:
        return self.data["profiles"][name]

    def researcher_effective_profile(self) -> dict:
        """Researcher settings with the 'follow main' defaults resolved (SPEC 11.2)."""
        researcher = dict(self.profile("researcher"))
        main = self.profile("main")
        if not researcher.get("provider"):
            researcher["provider"] = main["provider"]
            researcher["model"] = researcher.get("model") or main.get("model")
        return researcher

    def provider_enabled(self, provider: str) -> bool:
        return bool(self.data["providers"].get(provider, {}).get("enabled"))

    def get(self, dotted: str):
        node = self.data
        for part in dotted.split("."):
            if not isinstance(node, dict) or part not in node:
                raise fail(Failure.CONFIGURATION_INVALID, f"unknown configuration key {dotted!r}")
            node = node[part]
        return node

    def set(self, dotted: str, raw: str) -> None:
        parts = dotted.split(".")
        node = self.data
        for part in parts[:-1]:
            if not isinstance(node.get(part), dict):
                raise fail(Failure.CONFIGURATION_INVALID, f"unknown configuration key {dotted!r}")
            node = node[part]
        leaf = parts[-1]
        if leaf not in node:
            raise fail(Failure.CONFIGURATION_INVALID, f"unknown configuration key {dotted!r}")
        node[leaf] = _coerce(raw, node[leaf])
        validate(self.data)

    def save(self) -> None:
        validate(self.data)
        fsutil.atomic_write_json(self.paths.config_file, self.data)


def _coerce(raw: str, current: object) -> object:
    if raw in ("null", "none", ""):
        return None
    if isinstance(current, bool):
        if raw.lower() in ("true", "yes", "1"):
            return True
        if raw.lower() in ("false", "no", "0"):
            return False
        raise fail(Failure.CONFIGURATION_INVALID, f"expected true or false, got {raw!r}")
    if isinstance(current, int):
        try:
            return int(raw)
        except ValueError:
            raise fail(Failure.CONFIGURATION_INVALID, f"expected an integer, got {raw!r}") from None
    if isinstance(current, list):
        return [item.strip() for item in raw.split(",") if item.strip()]
    return raw


def validate(data: dict) -> None:
    problems: list[str] = []
    if data.get("schema") != SCHEMA:
        problems.append(f"schema must be {SCHEMA}")
    if data.get("network", {}).get("mode") not in NETWORK_MODES:
        problems.append(f"network.mode must be one of {', '.join(NETWORK_MODES)}")
    for name in ("main", "researcher", "search"):
        prof = data.get("profiles", {}).get(name, {})
        provider = prof.get("provider")
        if provider is not None and provider not in PROVIDERS:
            problems.append(f"profiles.{name}.provider must be one of {', '.join(PROVIDERS)}")
        thinking = prof.get("thinking")
        if name != "search" and thinking not in THINKING_LEVELS:
            problems.append(f"profiles.{name}.thinking must be one of {', '.join(THINKING_LEVELS)}")
        model = prof.get("model")
        if model is not None and (not isinstance(model, str) or "/" in model or ":" in model or not model.strip()):
            problems.append(f"profiles.{name}.model must be a bare model ID (no provider prefix or :thinking suffix)")
    fallback = data.get("profiles", {}).get("main", {}).get("thinking_fallback")
    if fallback is not None and fallback not in THINKING_LEVELS:
        problems.append("profiles.main.thinking_fallback must be a thinking level or null")
    for override in data.get("profiles", {}).get("researcher", {}).get("allowed_model_overrides", []) or []:
        if not isinstance(override, str) or override.count("/") != 1:
            problems.append("profiles.researcher.allowed_model_overrides entries must be provider/model")
    vault = data.get("vault", {})
    if not vault.get("study_dir") or "/" in vault.get("study_dir", "/") or vault.get("study_dir") in (".", ".."):
        problems.append("vault.study_dir must be a single directory name")
    if vault.get("path") and not Path(str(vault["path"])).expanduser().is_absolute():
        problems.append("vault.path must be absolute")
    for provider, loc in (data.get("infisical", {}).get("oauth_secrets") or {}).items():
        if provider not in PROVIDERS:
            problems.append(f"infisical.oauth_secrets.{provider} is not a known provider")
        elif not isinstance(loc, dict) or not str(loc.get("path", "")).startswith("/") or not re.fullmatch(r"[A-Z][A-Z0-9_]{1,127}", str(loc.get("name", ""))):
            problems.append(f"infisical.oauth_secrets.{provider} needs an absolute path and an UPPER_CASE secret name")
    sandbox_name = data.get("sandbox", {}).get("name", "")
    if not sandbox_name or not sandbox_name.replace("-", "").isalnum():
        problems.append("sandbox.name must be alphanumeric with dashes")
    if problems:
        raise fail(Failure.CONFIGURATION_INVALID, "; ".join(problems))


def load(paths: HostPaths, *, create: bool = False) -> Config:
    raw = fsutil.read_json(paths.config_file)
    if raw is None:
        if not create:
            raise fail(
                Failure.CONFIGURATION_INVALID,
                f"no configuration at {paths.config_file}",
                hint="run `study-room setup` first",
            )
        raw = {}
    if not isinstance(raw, dict):
        raise fail(Failure.CONFIGURATION_INVALID, f"{paths.config_file} is not a JSON object")
    data = _merge(DEFAULTS, raw)
    if not data.get("installation_id"):
        data["installation_id"] = str(uuid.uuid4())
    if not data["vault"].get("path"):
        data["vault"]["path"] = str(paths.default_vault_dir)
    validate(data)
    return Config(data, paths)
