"""`study-room verify --live`: explicit, consented, bounded live checks (SPEC 20.2-20.4).

Nothing here runs on a schedule or because a sandbox was rebuilt. Before any
request the exact model, thinking level, request cap, output cap, possible
search use and timeout are shown, and the user must type an explicit
confirmation. Checks use the lock's pinned cheap verification model at a low
reasoning level and refuse to fall back to the runtime teaching model.
"""

from __future__ import annotations

import json
import time
import uuid
from dataclasses import dataclass
from typing import Callable

from . import receipts
from .config import PI_PROVIDER_IDS, Config
from .errors import Failure, fail
from .lock import Lock
from .sbx import Sbx

COMPONENTS = ("provider", "research", "github", "obsidian")
PLACEHOLDER_ENV = {"openai": "OPENAI_API_KEY", "kimi": "KIMI_API_KEY"}
PLACEHOLDER_PREFIX = {"openai": "sr-openai-", "kimi": "sr-kimi-"}


@dataclass
class LiveSpec:
    provider: str
    model: str
    thinking: str
    limits: dict
    research_limits: dict

    def to_sandbox_json(self) -> str:
        return json.dumps(
            {
                "pi_provider": PI_PROVIDER_IDS[self.provider],
                "model": self.model,
                "thinking": self.thinking,
                "limits": self.limits,
                "research_limits": self.research_limits,
                "placeholder_env": PLACEHOLDER_ENV[self.provider],
                "placeholder_prefix": PLACEHOLDER_PREFIX[self.provider],
            }
        )


def spec_for(lock: Lock, config: Config, provider: str) -> LiveSpec:
    prof = lock.verification_model(provider)
    if prof.get("status") != "pinned":
        raise fail(
            Failure.CONFIGURATION_INVALID,
            f"the {provider} verification model is still a candidate ({prof.get('model')}), not a pin",
            hint=f"inspect the authenticated catalog with `study-room models {provider}`, then pin it with `study-room bump verification-model {provider} <id>` on a branch",
        )
    main = config.profile("main")
    if main.get("provider") == provider and main.get("model") == prof["model"]:
        raise fail(Failure.CONFIGURATION_INVALID, "the verification model must differ from the runtime teaching model")
    return LiveSpec(provider, prof["model"], prof["thinking"], prof["limits"], prof["research_limits"])


def disclosure(spec: LiveSpec, components: list[str]) -> list[str]:
    lines = [f"Live connectivity check for {spec.provider} (explicit; costs a small amount of provider usage):"]
    if "provider" in components:
        lines.append(
            f"  provider: model {PI_PROVIDER_IDS[spec.provider]}/{spec.model}, thinking {spec.thinking}, "
            f"at most {spec.limits['max_requests']} request(s), at most {spec.limits['max_output_tokens']} output tokens each, "
            f"timeout {spec.limits['timeout_seconds']}s, no search"
        )
    if "research" in components:
        r = spec.research_limits
        lines.append(
            f"  research: researcher loadout on {PI_PROVIDER_IDS[spec.provider]}/{spec.model}, thinking {spec.thinking}, "
            f"at most {r['max_model_turns']} model turns and {r['max_search_calls']} web_search call(s), "
            f"at most {r['max_output_tokens']} output tokens each, timeout {r['timeout_seconds']}s"
        )
    if "github" in components:
        lines.append("  github: read-only identity and repository checks (no pushes, no PRs, no settings)")
    if "obsidian" in components:
        lines.append("  obsidian: creates one uniquely named scratch note in Study Room/, checks it inside the sandbox, opens it in Obsidian, then deletes it")
    lines.append("These checks prove plumbing only. They never use the main teaching model and do not measure teaching or research quality.")
    return lines


def run(
    config: Config,
    lock: Lock,
    sbx: Sbx,
    provider: str,
    components: list[str],
    *,
    confirm: Callable[[list[str]], bool],
    open_in_obsidian: Callable[[str], None] | None = None,
    expected_github_login: str = "gej-machine",
    github_repo: str = "digigrant/study-room",
    say=print,
) -> dict[str, str]:
    for c in components:
        if c not in COMPONENTS:
            raise fail(Failure.CONFIGURATION_INVALID, f"unknown live component {c!r} (choose from {', '.join(COMPONENTS)})")
    needs_model = any(c in ("provider", "research") for c in components)
    spec = spec_for(lock, config, provider) if needs_model else LiveSpec(provider, "-", "-", {}, {})
    if not confirm(disclosure(spec, components)):
        raise fail(Failure.PERMISSION_DECLINED, "live checks were not confirmed; nothing was sent")
    if not sbx.exists():
        raise fail(Failure.MISSING_PREREQUISITE, "the Study Room sandbox does not exist", hint="run `study-room run` once first")
    results: dict[str, str] = {}

    def sandbox_check(name: str, payload: str) -> None:
        res = sbx.exec(["/opt/study-room/bin/study-room-live-check", name], input=payload, interactive=True)
        try:
            out = json.loads(res.stdout.strip().splitlines()[-1])
        except (ValueError, IndexError):
            out = {"status": "failed", "detail": (res.stderr or res.stdout).strip()[:200]}
        results[name] = out.get("status", "failed")
        say(f"  {name}: {out.get('status')} - {out.get('detail')}")

    if needs_model:
        sandbox_check("placeholder", spec.to_sandbox_json())
    for component in components:
        if component in ("provider", "research"):
            sandbox_check(component, spec.to_sandbox_json())
        elif component == "github":
            sandbox_check("github", json.dumps({"expected_login": expected_github_login, "repo": github_repo}))
        elif component == "obsidian":
            results["obsidian"] = _obsidian_scratch(config, sbx, open_in_obsidian, say)
    receipts.write(config, lock, provider, spec.model, results)
    return results


def _obsidian_scratch(config: Config, sbx: Sbx, open_in_obsidian, say) -> str:
    name = f"study-room-scratch-{time.strftime('%Y%m%d%H%M%S')}-{uuid.uuid4().hex[:8]}.md"
    note = config.study_dir / name
    note.write_text("Study Room live check scratch note. It is deleted automatically.\n", encoding="utf-8")
    try:
        res = sbx.exec(["test", "-f", f"/workspace/{name}"])
        if not res.ok:
            say("  obsidian: failed - the scratch note is not visible inside the sandbox")
            return "failed"
        if open_in_obsidian:
            open_in_obsidian(str(note))
            say(f"  obsidian: opened {name} in Obsidian; confirm you can see it, then press Enter")
            try:
                input()
            except EOFError:
                pass
        say("  obsidian: passed - the note was visible to the sandbox")
        say("  remote Sync still needs the one-time manual check on a second Obsidian client (docs/ACCEPTANCE.md)")
        return "passed"
    finally:
        note.unlink(missing_ok=True)
