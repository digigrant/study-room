"""`study-room run`: validate, start Obsidian, prepare the sandbox, enter (SPEC 8.5, 19).

The sandbox mounts only the vault's ``Study Room/`` directory read-write; it
appears inside at the same absolute path and as ``/workspace``. Credentials
reach it only as placeholders: Docker Sandboxes stores a command (an absolute
path and a provider name) and runs this checkout's resolver on the host when
it needs the real value.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path

from . import fsutil, image, network, obsidian, receipts, updates
from .config import PI_PROVIDER_IDS, Config
from .errors import Failure, fail
from .hostdetect import HostFacts
from .lock import Lock
from .paths import HostPaths, repo_root
from .runner import Runner
from .sbx import Sbx, resolver_command

PROVIDER_SECRETS = {
    # provider: (environment variable in the sandbox, destination hosts, placeholder pattern)
    "openai": ("OPENAI_API_KEY", ["api.openai.com"], "sr-openai-{rand}"),
    "kimi": ("KIMI_API_KEY", ["api.kimi.com"], "sr-kimi-{rand}"),
}


def study_room_bin() -> str:
    return str(repo_root() / "bin" / "study-room")


def register_secrets(sbx: Sbx, config: Config, *, bin_path: str | None = None) -> list[str]:
    """Sandbox-scoped, command-backed secrets. Returns change lines."""
    bin_path = bin_path or study_room_bin()
    existing = {s.env: s for s in sbx.custom_secrets()}
    refresh = config.data["secrets"]["refresh"]
    lines: list[str] = []
    for provider, (env, hosts, pattern) in PROVIDER_SECRETS.items():
        if config.provider_enabled(provider):
            current = existing.get(env)
            # Docker Sandboxes keeps one placeholder per variable and scope; reuse it.
            placeholder = current.placeholder if current else pattern
            sbx.set_custom(env=env, hosts=hosts, command=resolver_command(bin_path, provider), refresh=refresh, placeholder=placeholder)
            lines.append(f"{env}: placeholder for {', '.join(hosts)} resolved on the host by `study-room resolve {provider}`")
        elif env in existing:
            for host in hosts:
                sbx.remove_custom(env, host)
            lines.append(f"{env}: removed ({provider} is disabled)")
    if config.data["github"]["enabled"]:
        sbx.set_service("github", command=resolver_command(bin_path, "github"), refresh=config.data["secrets"]["github_refresh"])
        lines.append("github: gej-machine token placeholder resolved on the host by `study-room resolve github`")
    return lines


def host_summary(facts: HostFacts, obsidian_line: str) -> list[str]:
    platform = "Ubuntu" + (f" {facts.os_version}" if facts.os_version else "") + (" on WSL2" if facts.wsl2 else " (native)")
    display = {"wslg": "WSLg", "wayland": "Wayland", "x11": "X11"}.get(facts.display_kind or "", "no display")
    return [f"Host: {platform}, {display}, KVM {'ok' if facts.kvm_accessible else 'NOT accessible'}", obsidian_line]


def profile_payload(config: Config, lock: Lock, summary: list[str], warnings: list[str]) -> dict:
    main = config.profile("main")
    researcher = config.researcher_effective_profile()
    search = config.profile("search")
    providers = {
        name: {
            "enabled": config.provider_enabled(name),
            "experimental": bool(config.data["providers"][name].get("experimental", False)),
            "verified": receipts.verified(config, lock, name),
        }
        for name in config.data["providers"]
    }
    return {
        "schema": 1,
        "installation_id": config.installation_id,
        "network_mode": config.network_mode,
        "workspace": str(config.study_dir),
        "main": {
            "provider": main["provider"],
            "pi_provider": PI_PROVIDER_IDS[main["provider"]],
            "model": main.get("model"),
            "thinking": main["thinking"],
            "thinking_fallback": main.get("thinking_fallback"),
        },
        "researcher": {
            "provider": researcher["provider"],
            "pi_provider": PI_PROVIDER_IDS[researcher["provider"]],
            "model": researcher.get("model"),
            "thinking": researcher["thinking"],
            "allowed_model_overrides": list(researcher.get("allowed_model_overrides") or []),
        },
        "search": {
            "provider": search.get("provider") if search.get("model") else None,
            "pi_provider": PI_PROVIDER_IDS[search["provider"]] if search.get("model") and search.get("provider") else None,
            "model": search.get("model"),
        },
        "providers": providers,
        "host_summary": summary,
        "warnings": warnings,
        "lock_fingerprint": lock.fingerprint,
    }


def entry_warnings(config: Config, lock: Lock, drift: list[updates.Drift]) -> list[str]:
    warnings = list(updates.banner_lines(drift))
    for provider in config.data["providers"]:
        if config.provider_enabled(provider):
            warnings += receipts.warnings(config, lock, provider)
            if config.data["providers"][provider].get("experimental"):
                warnings.append(f"{provider} is EXPERIMENTAL until its live capability checks pass")
    return warnings


def preflight(config: Config, lock: Lock, runner: Runner) -> None:
    """Refuse to start with an incomplete configuration (explicit, classified failures)."""
    main = config.profile("main")
    if not main.get("model"):
        raise fail(
            Failure.CONFIGURATION_INVALID,
            "no main model is configured",
            hint=f"after `study-room auth {main['provider']}`, list the authenticated catalog with `study-room models {main['provider']}` and set one with `study-room config set profiles.main.model <id>`",
        )
    if not config.provider_enabled(main["provider"]):
        raise fail(Failure.CONFIGURATION_INVALID, f"the main provider {main['provider']} is disabled")
    researcher = config.researcher_effective_profile()
    if not config.provider_enabled(researcher["provider"]):
        raise fail(Failure.CONFIGURATION_INVALID, f"the researcher provider {researcher['provider']} is disabled")
    if not config.vault_path.is_dir():
        raise fail(Failure.VAULT_PATH_MISSING, f"the vault {config.vault_path} does not exist", hint="run `study-room obsidian setup`")
    if not config.study_dir.is_dir():
        raise fail(Failure.VAULT_PATH_MISSING, f"{config.study_dir} does not exist", hint="create the Study Room folder in Obsidian (`study-room obsidian setup`)")
    status = obsidian.vault_status(config, runner)
    for problem in status.problems:
        if "Git repository" in problem:
            raise fail(Failure.OBSIDIAN_NOT_CONFIGURED, problem)


@dataclass
class SandboxRecord:
    template: str
    workspace: str


def _record_path(paths: HostPaths, sandbox: str) -> Path:
    return paths.state_dir / f"sandbox-{sandbox}.json"


def ensure_sandbox(sbx: Sbx, paths: HostPaths, config: Config, template: str, *, say=print) -> str:
    """Create the sandbox, or recreate it when the image or workspace changed. Returns a status line."""
    record = fsutil.read_json(_record_path(paths, sbx.sandbox), {}) or {}
    workspace = str(config.study_dir)
    exists = sbx.exists()
    if exists and record.get("template") == template and record.get("workspace") == workspace:
        return "sandbox ready"
    if exists:
        say(
            "The sandbox image or workspace changed; recreating the sandbox. Disposable Pi sessions and scratch clones are discarded; "
            "notes in Study Room/ and host configuration are kept."
        )
        sbx.remove()
        network.forget(paths, sbx.sandbox)
    sbx.create(template, workspace)
    fsutil.atomic_write_json(_record_path(paths, sbx.sandbox), {"template": template, "workspace": workspace})
    return "sandbox created"


def forget_sandbox(paths: HostPaths, sandbox: str) -> None:
    try:
        _record_path(paths, sandbox).unlink()
    except FileNotFoundError:
        pass


def configure(sbx: Sbx, payload: dict) -> None:
    res = sbx.exec(["/opt/study-room/bin/study-room-configure"], user="root", input=json.dumps(payload), interactive=True)
    if not res.ok:
        raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, f"configuring the sandbox failed: {(res.stderr or res.stdout).strip()[:300]}")


def enabled_providers(config: Config) -> list[str]:
    return [p for p in config.data["providers"] if config.provider_enabled(p)]


def run(
    config: Config,
    lock: Lock,
    runner: Runner,
    facts: HostFacts,
    *,
    no_obsidian: bool = False,
    rebuild: bool = False,
    allow_sudo_docker: bool = False,
    drift: list[updates.Drift] | None = None,
    unlock_keyring=None,
    egress_check=None,
    say=print,
) -> int:
    preflight(config, lock, runner)
    from . import egress

    problems = (egress_check or (lambda: egress.check(os.getuid(), runner=runner)))()
    if problems:
        raise fail(
            Failure.MISSING_PREREQUISITE,
            "the host egress guard is not protecting the Docker Sandboxes daemon: " + "; ".join(p.message for p in problems),
            hint=problems[0].hint,
        )
    if unlock_keyring:
        unlock_keyring()
    obs_line = "Obsidian: skipped (--no-obsidian)"
    if not no_obsidian:
        status = obsidian.vault_status(config, runner)
        if not status.ok:
            raise fail(Failure.OBSIDIAN_NOT_CONFIGURED, status.summary(), hint="run `study-room obsidian setup`")
        obs_line = f"Obsidian: {obsidian.start_or_reuse(config, runner, say=say)}; {status.summary()}"
    sbx = Sbx(runner, config.sandbox_name)
    template = image.ensure(runner, sbx, lock, config.paths, rebuild=rebuild, allow_sudo=allow_sudo_docker, say=say)
    for line in register_secrets(sbx, config):
        say(f"secret {line}")
    say(ensure_sandbox(sbx, config.paths, config, template, say=say))
    for line in network.apply(sbx, config.paths, network.plan(config.network_mode, enabled_providers(config), github=config.data["github"]["enabled"])):
        say(f"network: {line}")
    warnings = entry_warnings(config, lock, drift or [])
    if config.network_mode == "balanced" and network.wider_than_balanced(sbx):
        warnings.append("Docker Sandboxes' global policy allows arbitrary destinations, so balanced mode is wider than intended; review `sbx policy ls`")
    payload = profile_payload(config, lock, host_summary(facts, obs_line), warnings)
    configure(sbx, payload)
    return sbx.attach(["/opt/study-room/bin/study-room-entry"])
