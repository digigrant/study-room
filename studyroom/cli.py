"""The `study-room` host command (SPEC 19).

Every subcommand runs on the trusted host. Responsibilities stay separate:
setup changes the host (with approval), auth runs provider ceremonies,
run enters the sandbox, verify sends explicitly approved live requests,
resolve is the non-interactive credential command Docker Sandboxes calls.
"""

from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import sys
import threading
import webbrowser
from pathlib import Path

from . import (
    config as configmod,
    doctor as doctormod,
    entry as entrymod,
    fsutil,
    hostdetect,
    image,
    lock as lockmod,
    network,
    obsidian,
    receipts,
    redact,
    setup as setupmod,
    testrunner,
    updates,
    verify as verifymod,
)
from .errors import Failure, StudyRoomError, fail
from .http import Client
from .infisical import Infisical, handles_from_keyring
from .keyring import Keyring
from .oauth import kimi as kimi_oauth
from .oauth import openai as openai_oauth
from .paths import host_paths, repo_root
from .resolver import OAuthLocation, Resolver, read_github_pat
from .runner import Runner
from .sbx import Sbx

PROVIDERS = ("openai", "kimi")


class Context:
    def __init__(self, runner: Runner | None = None, env: dict[str, str] | None = None):
        self.runner = runner or Runner()
        self.paths = host_paths(env)
        self._config: configmod.Config | None = None
        self._lock: lockmod.Lock | None = None

    @property
    def lock(self) -> lockmod.Lock:
        if self._lock is None:
            self._lock = lockmod.load()
        return self._lock

    def config(self, create: bool = False) -> configmod.Config:
        if self._config is None:
            self._config = configmod.load(self.paths, create=create)
        return self._config

    def keyring(self) -> Keyring:
        return Keyring(self.runner)

    def oauth_locations(self) -> dict[str, OAuthLocation]:
        secrets = self.config().data["infisical"]["oauth_secrets"]
        return {p: OAuthLocation(secrets[p]["path"], secrets[p]["name"]) for p in PROVIDERS}

    def infisical(self, *, interactive: bool = False) -> Infisical:
        inf = self.config().data["infisical"]
        writable = {(loc.path, loc.name) for loc in self.oauth_locations().values()}
        return Infisical(inf["domain"], inf["environment"], handles_from_keyring(self.keyring(), interactive=interactive), writable=writable)

    def resolver(self, *, interactive: bool = False) -> Resolver:
        cfg = self.config()
        return Resolver(self.infisical(interactive=interactive), self.paths, cfg.installation_id, self.oauth_locations())


# ── interaction helpers ────────────────────────────────────────────────────


def say(text: str = "") -> None:
    print(redact.redact_text(text), flush=True)


def ask_yes(question: str, *, default: bool = False) -> bool:
    if not sys.stdin.isatty():
        return False
    suffix = " [Y/n] " if default else " [y/N] "
    answer = input(question + suffix).strip().lower()
    return default if not answer else answer in ("y", "yes")


def typed_confirmation(lines: list[str], word: str = "yes") -> bool:
    for line in lines:
        say(line)
    if not sys.stdin.isatty():
        say("Not confirmed (no terminal).")
        return False
    return input(f'Type "{word}" to proceed: ').strip() == word


def open_browser(url: str) -> None:
    try:
        webbrowser.open(url, new=2)
    except Exception:  # noqa: BLE001 - the URL is also printed
        pass


# ── commands ───────────────────────────────────────────────────────────────


def cmd_setup(ctx: Context, args) -> int:
    lock = ctx.lock
    lockmod.require_valid(lock)
    cfg = ctx.config(create=True)
    cfg.save()
    fsutil.ensure_private_dir(ctx.paths.state_dir)
    fsutil.ensure_private_dir(ctx.paths.cache_dir)
    say(f"Study Room setup (installation {cfg.installation_id}); nothing changes without your approval.")
    facts = hostdetect.detect(hostdetect.Probe(ctx.runner))
    names = [p["name"] for p in lock["system_packages"]["host"]]
    installed = setupmod.installed_packages(ctx.runner, names)
    repo_ok = setupmod.docker_repo_configured()
    sbx_version = setupmod.sbx_candidate_version(ctx.runner, lock["docker_sandboxes"]["version"]) if repo_ok else None
    key_file = ctx.paths.downloads_dir / "docker.asc"

    def prepare_key() -> None:
        import urllib.request

        key_file.parent.mkdir(parents=True, exist_ok=True)
        with urllib.request.urlopen(lock["docker_apt_repository"]["key_url"], timeout=60) as resp:  # noqa: S310 - pinned URL
            key_file.write_bytes(resp.read())
        setupmod.verify_key_fingerprint(ctx.runner, key_file, lock["docker_apt_repository"]["key_fingerprint"])

    plan = setupmod.build_plan(
        facts,
        lock,
        ctx.paths,
        installed,
        sbx_apt_version=sbx_version,
        docker_repo_configured=repo_ok,
        prepare_obsidian=lambda: obsidian.download(ctx.paths, lock["obsidian_desktop"], say=say),
        prepare_docker_key=prepare_key,
    )
    for line in setupmod.render(plan):
        say(line)

    def approve(change: setupmod.Change) -> bool:
        if args.yes:
            say(f"approved by --yes: {change.title}")
            return True
        return ask_yes(f"Apply [{change.key}] {change.title}?")

    afters = setupmod.apply(plan, ctx.runner, approve, say=say)
    if afters:
        say("\nSome changes take effect only after a new login session:")
        for a in afters:
            say(f"  - {a}")
        say("Then run `study-room setup` again; finished steps are not repeated.")
        return 0
    if repo_ok is False and plan.changes:
        say("Run `study-room setup` again to continue with the steps that depend on the new packages.")
        return 0

    # Interactive ceremonies: never skipped by --yes (SPEC 16.1).
    facts = hostdetect.detect(hostdetect.Probe(ctx.runner))
    if facts.sbx_cli and not facts.sbx_logged_in:
        say("\nDocker Sandboxes needs you to sign in to Docker (interactive).")
        if ctx.runner.interactive(["sbx", "login"]) != 0:
            raise fail(Failure.PERMISSION_DECLINED, "Docker sign-in did not complete")
    infisical_ceremony(ctx)
    cmd_obsidian_setup(ctx, args)
    main_provider = cfg.profile("main")["provider"]
    if ask_yes(f"Authorize {main_provider} now (opens a browser)?", default=True):
        cmd_auth(ctx, argparse.Namespace(provider=main_provider))
    say("\nSetup complete. Next: `study-room models openai`, set the main model, then `study-room run`.")
    return 0


def infisical_ceremony(ctx: Context) -> None:
    kr = ctx.keyring()
    kr.require_tools()
    states = kr.states()
    if "locked" in states.values():
        kr.unlock_interactively()
        states = kr.states()
    missing = [k for k, v in states.items() if v == "missing"]
    if missing:
        say("\nStudy Room uses the existing Infisical sbx-host machine identity, stored in its own keyring namespace.")
        say("Create a client secret for this machine on the Infisical website (sbx-host → Universal Auth), then paste the values.")
        say("Input is hidden; values go straight to the Secret Service and are never written elsewhere.")
        if not sys.stdin.isatty():
            raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, "Infisical handles are missing and no terminal is available to enter them")
        prompts = {"infisical-project-id": "Infisical project ID: ", "infisical-client-id": "sbx-host client ID: ", "infisical-client-secret": "sbx-host client secret: "}
        for key in missing:
            value = getpass.getpass(prompts[key]).strip()
            if not value:
                raise fail(Failure.PERMISSION_DECLINED, f"no value entered for {key}")
            kr.store(key, value)
    inf = ctx.infisical(interactive=True)
    cfg = ctx.config()
    pat = read_github_pat(inf, cfg.data["infisical"]["github_secret_path"], cfg.data["infisical"]["github_secret_name"])
    shape = "ghp_…" if pat.startswith("ghp_") else "github_pat_…" if pat.startswith("github_pat_") else "unexpected shape"
    say(f"Infisical: ok; {cfg.data['infisical']['github_secret_name']} readable ({len(pat)} chars, {shape})")


def cmd_obsidian_setup(ctx: Context, args) -> int:
    cfg = ctx.config(create=True)
    vault = cfg.vault_path
    if not vault.exists():
        vault.mkdir(parents=True, mode=0o700)
        say(f"Created {vault} for the fresh Linux replica.")
    say(obsidian.ONBOARDING.format(vault=vault, study_dir=cfg.data["vault"]["study_dir"]))
    binary = ctx.runner.which("obsidian") or (obsidian.APP_BINARY if Path(obsidian.APP_BINARY).exists() else None)
    if binary and (os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY")) and not obsidian.running(ctx.runner):
        ctx.runner.spawn_detached([binary])
    if sys.stdin.isatty():
        input("Press Enter when Sync has finished...")
    status = obsidian.vault_status(cfg, ctx.runner)
    if not cfg.study_dir.is_dir() and vault.is_dir() and (vault / ".obsidian").is_dir():
        if ask_yes(f'There is no "{cfg.data["vault"]["study_dir"]}" folder in the vault. Create it (Sync will upload it)?'):
            cfg.study_dir.mkdir()
            status = obsidian.vault_status(cfg, ctx.runner)
    say(status.summary())
    for w in status.warnings:
        say(f"  warning: {w}")
    return 0 if status.ok else 1


def cmd_auth(ctx: Context, args) -> int:
    provider = args.provider
    cfg = ctx.config()
    resolver = ctx.resolver(interactive=True)
    client = Client(timeout=60)

    def ask(prompt: str) -> str:
        return getpass.getpass(prompt)

    if provider == "openai":
        state = openai_oauth.login(client, cfg.installation_id, say=say, open_browser=open_browser, ask=ask)
    else:
        state = kimi_oauth.login(client, cfg.installation_id, say=say, open_browser=open_browser)
    name = ctx.oauth_locations()[provider].name

    def replace_foreign() -> bool:
        return ask_yes(f"The Infisical secret {name} holds a value Study Room did not write. Replace it with Study Room's authorization state?")

    resolver.save_new(state, replace_foreign=replace_foreign)
    say(f"Authorized: {state.describe()}. Stored in Infisical secret {name} under this host's installation ID; the sandbox will see a placeholder.")
    if provider == "kimi" and not cfg.provider_enabled("kimi"):
        say("Kimi stays disabled and experimental. Enable it explicitly with `study-room config set providers.kimi.enabled true` after its live checks.")
    return 0


def cmd_models(ctx: Context, args) -> int:
    provider = args.provider
    resolver = ctx.resolver(interactive=True)
    token = resolver.access_token(provider)
    client = Client(timeout=60)
    ids = openai_oauth.list_models(client, token) if provider == "openai" else kimi_oauth.list_models(client, token)
    cfg = ctx.config()
    marks = {
        cfg.profile("main").get("model"): "main",
        cfg.researcher_effective_profile().get("model"): "researcher",
        cfg.profile("search").get("model"): "search",
        ctx.lock.verification_model(provider)["model"]: f"verification ({ctx.lock.verification_model(provider)['status']})",
    }
    say(f"Models in the authenticated {provider} catalog ({len(ids)}):")
    for mid in ids:
        tag = marks.get(mid)
        say(f"  {mid}{f'   <- {tag}' if tag else ''}")
    for mid, tag in marks.items():
        if mid and mid not in ids:
            say(f"WARNING: the {tag} model {mid} is not in this catalog ({Failure.MODEL_NOT_IN_CATALOG.value})")
    return 0


def cmd_resolve(ctx: Context, args) -> int:
    """Non-interactive: value on stdout, one redacted line on stderr on failure."""
    name = args.name
    cfg = ctx.config()
    if name == "github":
        inf = ctx.infisical()
        value = read_github_pat(inf, cfg.data["infisical"]["github_secret_path"], cfg.data["infisical"]["github_secret_name"])
    elif name in PROVIDERS:
        if not cfg.provider_enabled(name):
            raise fail(Failure.CREDENTIALS_NOT_CONFIGURED, f"{name} is disabled in Study Room configuration")
        value = ctx.resolver().access_token(name)
    else:
        raise fail(Failure.CONFIGURATION_INVALID, f"unknown secret {name!r}")
    sys.stdout.write(value + "\n")
    sys.stdout.flush()
    return 0


def _facts(ctx: Context) -> hostdetect.HostFacts:
    return hostdetect.detect(hostdetect.Probe(ctx.runner))


def _drift(ctx: Context, *, blocking: bool) -> list[updates.Drift]:
    cfg = ctx.config()
    client = Client(timeout=updates.TIMEOUT)
    refresh = lambda: updates.check(ctx.lock, client, ctx.runner)  # noqa: E731
    if blocking:
        return updates.cached(ctx.paths, ctx.lock, cfg.data["updates"]["interval_hours"], refresh, force=True)[0]
    results, fresh = updates.read_cache(ctx.paths, ctx.lock, cfg.data["updates"]["interval_hours"])
    if not fresh:
        # Use the cache now; refresh in the background so entry never waits on an update service.
        threading.Thread(target=lambda: updates.cached(ctx.paths, ctx.lock, cfg.data["updates"]["interval_hours"], refresh), daemon=True).start()
    return results


def cmd_run(ctx: Context, args) -> int:
    lockmod.require_valid(ctx.lock)
    cfg = ctx.config()
    facts = _facts(ctx)
    if facts.sbx_version != ctx.lock["docker_sandboxes"]["version"]:
        raise fail(Failure.PIN_MISMATCH, f"Docker Sandboxes {facts.sbx_version or 'is not installed'}; Study Room is pinned to {ctx.lock['docker_sandboxes']['version']}", hint="run `study-room setup`")
    kr = ctx.keyring()

    def unlock() -> None:
        if "locked" in kr.states().values():
            say("Unlocking the keyring (a desktop prompt may appear)...")
            kr.unlock_interactively()

    code = entrymod.run(
        cfg,
        ctx.lock,
        ctx.runner,
        facts,
        no_obsidian=args.no_obsidian,
        rebuild=args.rebuild,
        allow_sudo_docker=args.sudo_docker,
        drift=_drift(ctx, blocking=False),
        unlock_keyring=unlock,
        say=say,
    )
    return code


def cmd_doctor(ctx: Context, args) -> int:
    findings = doctormod.host_findings(_facts(ctx), ctx.lock)
    try:
        cfg = ctx.config()
        findings += doctormod.config_findings(cfg, ctx.lock, ctx.runner, ctx.keyring())
        if not args.host_only:
            findings += doctormod.sandbox_findings(cfg, ctx.runner)
    except StudyRoomError as exc:
        findings.append(doctormod.Finding(doctormod.FAIL, "config", exc.message))
    for line in doctormod.render(findings):
        say(line)
    return doctormod.exit_code(findings)


def cmd_network(ctx: Context, args) -> int:
    cfg = ctx.config()
    desired = network.plan(args.mode, entrymod.enabled_providers(cfg), github=cfg.data["github"]["enabled"])
    lines = desired.describe() + [f"Change the network mode from {cfg.network_mode} to {args.mode}?"]
    if args.mode == "web" and not typed_confirmation(lines, "web"):
        raise fail(Failure.PERMISSION_DECLINED, "network mode unchanged")
    if args.mode == "balanced":
        for line in lines[:-1]:
            say(line)
    cfg.data["network"]["mode"] = args.mode
    cfg.save()
    sbx = Sbx(ctx.runner, cfg.sandbox_name)
    if sbx.exists():
        for line in network.apply(sbx, ctx.paths, desired):
            say(f"network: {line}")
        say("The sandbox's rules changed now; the banner shows the new mode at the next `study-room run`.")
    else:
        say("Saved; the rules are applied when the sandbox is created by `study-room run`.")
    return 0


def cmd_build(ctx: Context, args) -> int:
    sbx = Sbx(ctx.runner, ctx.config().sandbox_name)
    tag = image.ensure(ctx.runner, sbx, ctx.lock, ctx.paths, rebuild=args.no_cache, allow_sudo=args.sudo_docker, say=say)
    say(f"Template ready: {tag}")
    return 0


def cmd_test(ctx: Context, args) -> int:
    return testrunner.run(ctx.runner, build=args.build, only=args.only)


def cmd_verify(ctx: Context, args) -> int:
    if not args.live:
        raise fail(Failure.CONFIGURATION_INVALID, "live verification must be requested explicitly: `study-room verify --live [component...]`")
    cfg = ctx.config()
    components = args.components or ["provider"]
    if "infisical" in components:
        components = [c for c in components if c != "infisical"]
        verify_infisical_access(ctx)
        if not components:
            return 0
    sbx = Sbx(ctx.runner, cfg.sandbox_name)
    results = verifymod.run(
        cfg,
        ctx.lock,
        sbx,
        args.provider,
        components,
        confirm=typed_confirmation,
        open_in_obsidian=lambda note: ctx.runner.spawn_detached([ctx.runner.which("obsidian") or obsidian.APP_BINARY, obsidian.open_uri(Path(note))]),
        say=say,
    )
    return 1 if "failed" in results.values() else 0


def verify_infisical_access(ctx: Context) -> None:
    """Live gate (SPEC 26): can sbx-host read the GitHub token and read and write the OAuth secrets?"""
    cfg = ctx.config()
    inf = ctx.infisical(interactive=True)
    locations = {p: loc for p, loc in ctx.oauth_locations().items() if cfg.provider_enabled(p)}
    lines = [
        "Infisical access check (no provider requests):",
        f"  1. read {cfg.data['infisical']['github_secret_name']} (only its length and shape are shown)",
        *[f"  2. read {loc.name} and write its current value back unchanged ({p})" for p, loc in locations.items()],
        "  Per the captain's decision of 2026-10-06, sbx-host writes these secrets in the Agents project;",
        "  Study Room's client refuses to write any other secret.",
    ]
    if not typed_confirmation(lines):
        raise fail(Failure.PERMISSION_DECLINED, "Infisical check not confirmed")
    token = inf.session_token()
    try:
        pat = inf.get(cfg.data["infisical"]["github_secret_path"], cfg.data["infisical"]["github_secret_name"], token=token)
        say(f"  github token: {'readable (' + str(len(pat)) + ' chars)' if pat else 'MISSING'}")
        for provider, loc in locations.items():
            value = inf.get(loc.path, loc.name, token=token)
            if value is None:
                say(f"  {loc.name}: does not exist yet; `study-room auth {provider}` creates it")
                continue
            inf.put(loc.path, loc.name, value, exists=True, token=token)
            same = inf.get(loc.path, loc.name, token=token) == value
            say(f"  {loc.name}: readable and writable{'' if same else ' (WARNING: the value changed between write and read)'}")
    finally:
        inf.revoke(token)


def cmd_check_updates(ctx: Context, args) -> int:
    cfg = ctx.config()
    results, checked = updates.cached(ctx.paths, ctx.lock, cfg.data["updates"]["interval_hours"], lambda: updates.check(ctx.lock, Client(timeout=updates.TIMEOUT), ctx.runner), force=args.refresh)
    for line in updates.render(results, checked):
        say(line)
    return 0


def cmd_bump(ctx: Context, args) -> int:
    from . import bump as bumpmod

    def rebuild(new_lock: lockmod.Lock) -> None:
        image.build(ctx.runner, new_lock, image.image_tag(new_lock), no_cache=True, say=say)

    return bumpmod.run(
        args.dependency,
        args.args,
        runner=ctx.runner,
        client=Client(timeout=60),
        to=args.to,
        confirm=lambda lines: typed_confirmation(lines),
        run_tests=lambda: testrunner.run(ctx.runner),
        rebuild=rebuild,
        say=say,
    )


def cmd_destroy(ctx: Context, args) -> int:
    cfg = ctx.config()
    sbx = Sbx(ctx.runner, cfg.sandbox_name)
    say(f"This removes the sandbox {cfg.sandbox_name!r}: Pi sessions, researcher artifacts, scratch clones and its sandbox-scoped secrets and rules.")
    say(f"It does NOT touch the vault ({cfg.vault_path}) or trusted host configuration.")
    if not args.yes and not ask_yes("Remove the sandbox?"):
        raise fail(Failure.PERMISSION_DECLINED, "nothing removed")
    if sbx.exists():
        sbx.remove()
        say("Sandbox removed.")
    else:
        say("No sandbox to remove.")
    network.forget(ctx.paths, cfg.sandbox_name)
    entrymod.forget_sandbox(ctx.paths, cfg.sandbox_name)
    if args.remove_templates:
        for name in sorted(sbx.template_names()):
            if name.startswith(ctx.lock["sandbox_image"]["repository"] + ":"):
                sbx.template_rm(name)
                say(f"Removed template {name}")
    if args.purge_host_state:
        targets = [ctx.paths.config_dir, ctx.paths.state_dir, ctx.paths.cache_dir]
        lines = ["Durable host state will be deleted:"] + [f"  {t}" for t in targets] + [
            "This includes the installation ID and receipts. The vault, the keyring entries and Infisical OAuth state are NOT deleted."
        ]
        if typed_confirmation(lines, "delete"):
            for t in targets:
                if fsutil.is_within(cfg.vault_path, t):
                    raise fail(Failure.INTERNAL, f"refusing to delete {t}: it contains the vault")
                shutil.rmtree(t, ignore_errors=True)
            say("Host state deleted.")
        else:
            say("Host state kept.")
    return 0


def cmd_config(ctx: Context, args) -> int:
    cfg = ctx.config(create=args.action == "show")
    if args.action == "show":
        say(json.dumps(cfg.data, indent=2, sort_keys=True))
    elif args.action == "get":
        say(json.dumps(cfg.get(args.key)))
    elif args.action == "set":
        if args.key == "network.mode":
            raise fail(Failure.CONFIGURATION_INVALID, "change the network mode with `study-room network balanced|web`")
        cfg.set(args.key, args.value)
        cfg.save()
        say(f"{args.key} = {json.dumps(cfg.get(args.key))}")
    return 0


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="study-room", description="Study Room: Pi teaching sessions in a Docker Sandbox with a graphical Obsidian vault.")
    sub = p.add_subparsers(dest="command", required=True)
    s = sub.add_parser("setup", help="detect the host, show and apply approved changes, run sign-in ceremonies")
    s.add_argument("--yes", action="store_true", help="approve proposed host changes (sign-in ceremonies still ask)")
    s.set_defaults(fn=cmd_setup)
    s = sub.add_parser("doctor", help="report host and sandbox readiness without changing anything")
    s.add_argument("--host-only", action="store_true")
    s.set_defaults(fn=cmd_doctor)
    s = sub.add_parser("auth", help="authorize a provider on this host (stored in Infisical)")
    s.add_argument("provider", choices=PROVIDERS)
    s.set_defaults(fn=cmd_auth)
    s = sub.add_parser("models", help="list the authenticated provider catalog")
    s.add_argument("provider", choices=PROVIDERS)
    s.set_defaults(fn=cmd_models)
    s = sub.add_parser("obsidian", help="Obsidian Desktop vault onboarding")
    s.add_argument("action", choices=["setup"])
    s.set_defaults(fn=cmd_obsidian_setup)
    s = sub.add_parser("network", help="switch the sandbox network mode")
    s.add_argument("mode", choices=network.MODES)
    s.set_defaults(fn=cmd_network)
    s = sub.add_parser("run", help="start Obsidian and enter the Study Room sandbox")
    s.add_argument("--no-obsidian", action="store_true", help="skip the GUI (maintenance and troubleshooting)")
    s.add_argument("--rebuild", action="store_true", help="rebuild the sandbox image from scratch first")
    s.add_argument("--sudo-docker", action="store_true", help="allow `sudo docker` for the image build")
    s.set_defaults(fn=cmd_run)
    s = sub.add_parser("build", help="build and load the sandbox image")
    s.add_argument("--no-cache", action="store_true")
    s.add_argument("--sudo-docker", action="store_true")
    s.set_defaults(fn=cmd_build)
    s = sub.add_parser("test", help="run the hermetic test suites (no credentials, providers or vault)")
    s.add_argument("--build", action="store_true", help="build the sandbox image if it is missing")
    s.add_argument("--only", choices=["host", "sandbox"])
    s.set_defaults(fn=cmd_test)
    s = sub.add_parser("verify", help="explicit live connectivity checks")
    s.add_argument("--live", action="store_true", required=True)
    s.add_argument("--provider", choices=PROVIDERS, default="openai")
    s.add_argument("components", nargs="*", help=f"any of: {', '.join(verifymod.COMPONENTS + ('infisical',))} (default: provider)")
    s.set_defaults(fn=cmd_verify)
    s = sub.add_parser("check-updates", help="show dependency drift (installs nothing)")
    s.add_argument("--refresh", action="store_true")
    s.set_defaults(fn=cmd_check_updates)
    s = sub.add_parser("bump", help="move one pin on a branch, rebuild and test")
    s.add_argument("dependency")
    s.add_argument("args", nargs="*")
    s.add_argument("--to")
    s.set_defaults(fn=cmd_bump)
    s = sub.add_parser("destroy", help="remove the sandbox (keeps the vault and host configuration)")
    s.add_argument("--yes", action="store_true")
    s.add_argument("--remove-templates", action="store_true")
    s.add_argument("--purge-host-state", action="store_true", help="also delete host config/state/cache (asks first)")
    s.set_defaults(fn=cmd_destroy)
    s = sub.add_parser("config", help="show or change trusted host configuration")
    s.add_argument("action", choices=["show", "get", "set"])
    s.add_argument("key", nargs="?")
    s.add_argument("value", nargs="?")
    s.set_defaults(fn=cmd_config)
    s = sub.add_parser("resolve", description="internal: print a credential for Docker Sandboxes (stdout only)")
    s.add_argument("name")
    s.set_defaults(fn=cmd_resolve)
    return p


def main(argv: list[str] | None = None, ctx: Context | None = None) -> int:
    args = parser().parse_args(argv)
    ctx = ctx or Context()
    try:
        return args.fn(ctx, args)
    except StudyRoomError as exc:
        print(exc.render(), file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:
        print("study-room: interrupted", file=sys.stderr)
        return 130
    except Exception as exc:  # noqa: BLE001 - last line of defence: never print secrets
        print(f"study-room: internal error: {redact.redact_text(exc)}", file=sys.stderr)
        return 70
