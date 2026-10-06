"""`study-room doctor`: host and sandbox readiness, without changing anything.

It reports, it does not repair: every finding names the command that fixes
it. No secret value is printed; keyring entries and Infisical state are
reported as present or missing only.
"""

from __future__ import annotations

import json
from dataclasses import dataclass

from . import lock as lockmod
from . import network, obsidian, receipts
from .config import Config
from .errors import StudyRoomError
from .hostdetect import HostFacts
from .keyring import Keyring
from .runner import Runner
from .sbx import Sbx

OK, WARN, FAIL = "ok", "warn", "FAIL"


@dataclass
class Finding:
    level: str
    area: str
    detail: str


def host_findings(facts: HostFacts, lock: lockmod.Lock) -> list[Finding]:
    f: list[Finding] = []
    platform_ok = facts.os_id == "ubuntu" and facts.os_version == "24.04" and facts.machine in ("x86_64", "amd64")
    f.append(Finding(OK if platform_ok else FAIL, "platform", f"{facts.os_pretty or facts.os_id} {facts.machine}{' (WSL2)' if facts.wsl2 else ''}"))
    f.append(Finding(OK if facts.display_kind else FAIL, "display", facts.display_kind or "no graphical session"))
    f.append(Finding(OK if facts.systemd_system and facts.systemd_user else FAIL, "systemd", "system and user managers running" if facts.systemd_system and facts.systemd_user else "systemd or the user session is missing"))
    f.append(Finding(OK if facts.kvm_accessible else FAIL, "kvm", "/dev/kvm accessible" if facts.kvm_accessible else "/dev/kvm missing or not accessible (kvm group; log out and in)"))
    f.append(Finding(OK if facts.secret_tool and facts.secret_service else FAIL, "keyring", "Secret Service answers" if facts.secret_service else "no Secret Service on the session bus"))
    pin = lock["docker_sandboxes"]["version"]
    if not facts.sbx_cli:
        f.append(Finding(FAIL, "docker sandboxes", "sbx not installed (`study-room setup`)"))
    else:
        f.append(Finding(OK if facts.sbx_version == pin else FAIL, "docker sandboxes", f"sbx {facts.sbx_version or 'unknown'} (pinned {pin})"))
        f.append(Finding(OK if facts.sbx_logged_in else WARN, "docker login", "signed in" if facts.sbx_logged_in else "run `sbx login`"))
        f.append(Finding(OK if facts.sbx_policy_initialized else FAIL, "sandbox policy", "initialized" if facts.sbx_policy_initialized else "not initialized (`study-room setup`)"))
    obs = lock["obsidian_desktop"]["version"]
    f.append(Finding(OK if facts.obsidian_installed_version == obs else FAIL, "obsidian", f"installed {facts.obsidian_installed_version or 'no'} (pinned {obs})"))
    return f


def config_findings(config: Config, lock: lockmod.Lock, runner: Runner, keyring: Keyring) -> list[Finding]:
    f: list[Finding] = []
    problems = lockmod.validate(lock)
    f.append(Finding(OK if not problems else FAIL, "lock", "lock manifest consistent" if not problems else "; ".join(problems[:3])))
    status = obsidian.vault_status(config, runner)
    f.append(Finding(OK if status.ok else FAIL, "vault", status.summary()))
    try:
        states = keyring.states()
        missing = [k for k, v in states.items() if v == "missing"]
        locked = [k for k, v in states.items() if v == "locked"]
        if missing:
            f.append(Finding(FAIL, "infisical handles", f"missing from the keyring: {', '.join(missing)} (`study-room setup`)"))
        elif locked:
            f.append(Finding(WARN, "infisical handles", "keyring locked; `study-room run` unlocks it"))
        else:
            f.append(Finding(OK, "infisical handles", "present in the study-room keyring namespace"))
    except StudyRoomError as exc:
        f.append(Finding(FAIL, "infisical handles", exc.message))
    main = config.profile("main")
    f.append(Finding(OK if main.get("model") else FAIL, "main model", f"{main['provider']}/{main.get('model') or 'unset'} thinking {main['thinking']}"))
    r = config.researcher_effective_profile()
    f.append(Finding(OK if r.get("model") else FAIL, "researcher model", f"{r['provider']}/{r.get('model') or 'unset'} thinking {r['thinking']}"))
    f.append(Finding(OK, "network mode", f"{config.network_mode} (recorded on the sandbox: {network.recorded_mode(config.paths, config.sandbox_name) or 'not applied yet'})"))
    for provider in config.data["providers"]:
        if config.provider_enabled(provider):
            ws = receipts.warnings(config, lock, provider)
            f.append(Finding(WARN if ws else OK, f"{provider} live check", "; ".join(ws) if ws else "verified for the current pins and configuration"))
            if config.data["providers"][provider].get("experimental"):
                f.append(Finding(WARN, provider, "EXPERIMENTAL until its capability gate passes"))
    return f


def egress_findings(runner: Runner, uid: int, check=None) -> list[Finding]:
    from . import egress

    problems = (check or (lambda: egress.check(uid, runner=runner)))()
    if not problems:
        return [Finding(OK, "egress guard", f"the Docker Sandboxes daemon runs inside {egress.UNIT}; private and link-local destinations are rejected")]
    return [Finding(FAIL, "egress guard", f"{p.message} (fix: {p.hint})") for p in problems]


def sandbox_findings(config: Config, runner: Runner) -> list[Finding]:
    sbx = Sbx(runner, config.sandbox_name)
    try:
        if not sbx.exists():
            return [Finding(WARN, "sandbox", "not created yet (`study-room run`)")]
    except StudyRoomError as exc:
        return [Finding(WARN, "sandbox", exc.message)]
    res = sbx.exec(["/opt/study-room/bin/study-room-diagnose", "--json"])
    try:
        report = json.loads(res.stdout)
    except ValueError:
        return [Finding(FAIL, "sandbox", f"diagnostics did not run: {(res.stderr or res.stdout).strip()[:200]}")]
    return [Finding(OK if c["ok"] else FAIL, f"sandbox {c['name']}", c["detail"]) for c in report.get("checks", [])]


def render(findings: list[Finding]) -> list[str]:
    return [f"{x.level:<4} {x.area}: {x.detail}" for x in findings]


def exit_code(findings: list[Finding]) -> int:
    return 1 if any(x.level == FAIL for x in findings) else 0
