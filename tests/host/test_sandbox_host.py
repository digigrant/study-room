"""Network policy, vault-mount boundary, placeholders, entry, updates, receipts, live-check consent,
Obsidian, destroy and bump (SPEC 9, 13, 15, 18, 19, 20)."""

from __future__ import annotations

import io
import json
import subprocess
import time
from contextlib import redirect_stdout
from pathlib import Path

from studyroom import bump, cli, entry, network, obsidian, receipts, updates, verify
from studyroom import lock as lockmod
from studyroom.errors import Failure, StudyRoomError
from studyroom.hostdetect import FixtureProbe, detect
from studyroom.paths import repo_root
from studyroom.runner import FakeRunner, Result
from studyroom.sbx import Sbx, resolver_command

from tests.host.helpers import TempHome, git_runner, host_fixture

LOCK = lockmod.load()


class FakeSbx:
    """Records sbx invocations and keeps minimal state, like Docker Sandboxes 0.46."""

    def __init__(self) -> None:
        self.runner = FakeRunner(available={"sbx"})
        self.sandboxes: list[dict] = []
        self.custom: list[dict] = []
        self.runner.on(["sbx", "ls", "--json"], lambda argv, _i: Result(argv, 0, json.dumps({"sandboxes": self.sandboxes})))
        self.runner.on(["sbx", "secret", "ls"], lambda argv, _i: Result(argv, 0, json.dumps({"secrets": [], "custom_secrets": self.custom})))
        self.runner.on(["sbx", "secret", "set-custom"], self._set_custom)
        self.runner.on(["sbx", "secret", "set"], 0)
        self.runner.on(["sbx", "secret", "rm"], 0)
        self.runner.on(["sbx", "policy"], 0)
        self.runner.on(["sbx", "create"], self._create)
        self.runner.on(["sbx", "rm"], self._rm)
        self.runner.on(["sbx", "exec"], 0)
        self.runner.on(["sbx", "template", "ls"], "[]")

    def _set_custom(self, argv, _i):
        env = argv[argv.index("--env") + 1]
        ph = argv[argv.index("--placeholder") + 1].replace("{rand}", "r4nd0m")
        existing = next((c for c in self.custom if c["env"] == env), None)
        if existing and existing["placeholder"] != ph:
            return Result(argv, 1, "", f'error: custom secret env "{env}" already exists with placeholder "{existing["placeholder"]}"')
        if not existing:
            self.custom.append({"scope": argv[argv.index("--sandbox") + 1], "env": env, "placeholder": ph, "targets": [argv[argv.index("--host") + 1]], "source": argv[argv.index("--command") + 1]})
        return Result(argv, 0, "")

    def _create(self, argv, _i):
        self.sandboxes.append({"name": argv[argv.index("--name") + 1], "status": "running"})
        return Result(argv, 0, "")

    def _rm(self, argv, _i):
        self.sandboxes = [s for s in self.sandboxes if s["name"] not in argv]
        return Result(argv, 0, "")

    def calls(self, *prefix: str) -> list[list[str]]:
        return [a for a in self.runner.argvs() if a[: len(prefix)] == list(prefix)]


class NetworkTests(TempHome):
    def test_balanced_allows_only_needed_destinations(self) -> None:
        p = network.plan("balanced", ["openai"])
        self.assertIn("api.openai.com:443", p.allow)
        self.assertIn("github.com:443", p.allow)
        self.assertNotIn("**:443", p.allow)
        self.assertNotIn("auth.openai.com:443", p.allow, "authorization happens on the host, not in the sandbox")
        self.assertNotIn("api.kimi.com:443", p.allow, "disabled providers get no egress")
        for internal in ("host.docker.internal", "169.254.169.254", "10.0.0.0/8", "localhost"):
            self.assertIn(internal, p.deny)

    def test_web_adds_public_http_on_80_and_443_only(self) -> None:
        p = network.plan("web", ["openai"])
        self.assertIn("**:443", p.allow)
        self.assertIn("**:80", p.allow)
        self.assertNotIn("**", p.allow, "no unrestricted allow-all")
        self.assertTrue(any("send study notes" in line for line in p.describe()))

    def test_rules_are_sandbox_scoped_denies_first_and_mode_switch_is_precise(self) -> None:
        fake = FakeSbx()
        sbx = Sbx(fake.runner, "study-room")
        network.apply(sbx, self.paths, network.plan("balanced", ["openai"]))
        policy_calls = fake.calls("sbx", "policy")
        self.assertTrue(policy_calls)
        for argv in policy_calls:
            self.assertIn("--sandbox", argv)
            self.assertEqual(argv[argv.index("--sandbox") + 1], "study-room")
            self.assertNotIn("init", argv, "never touches global policy")
        kinds = [a[2] for a in policy_calls]
        self.assertEqual(kinds, ["deny", "allow"])
        fake.runner.calls.clear()
        network.apply(sbx, self.paths, network.plan("web", ["openai"]))
        adds = [a for a in fake.calls("sbx", "policy", "allow")]
        self.assertEqual(adds[0][-1], "**:443,**:80")
        self.assertEqual(fake.calls("sbx", "policy", "rm"), [], "switching to web removes nothing")
        fake.runner.calls.clear()
        network.apply(sbx, self.paths, network.plan("balanced", ["openai"]))
        removed = sorted(a[a.index("--resource") + 1] for a in fake.calls("sbx", "policy", "rm"))
        self.assertEqual(removed, ["**:443", "**:80"])
        self.assertEqual(network.recorded_mode(self.paths, "study-room"), "balanced")
        fake.runner.calls.clear()
        network.apply(sbx, self.paths, network.plan("balanced", ["openai"]))
        self.assertEqual(fake.calls("sbx", "policy"), [], "idempotent")


class EntryTests(TempHome):
    def test_secrets_are_placeholders_backed_by_the_host_resolver(self) -> None:
        cfg = self.make_config()
        fake = FakeSbx()
        sbx = Sbx(fake.runner, "study-room")
        entry.register_secrets(sbx, cfg, bin_path="/home/learner/study-room/bin/study-room")
        custom = fake.calls("sbx", "secret", "set-custom")[0]
        self.assertEqual(custom[custom.index("--env") + 1], "OPENAI_API_KEY")
        self.assertEqual(custom[custom.index("--host") + 1], "api.openai.com")
        self.assertEqual(custom[custom.index("--placeholder") + 1], "sr-openai-{rand}")
        self.assertEqual(custom[custom.index("--command") + 1], "/home/learner/study-room/bin/study-room resolve openai")
        self.assertEqual(custom[custom.index("--sandbox") + 1], "study-room")
        github = fake.calls("sbx", "secret", "set")[0]
        self.assertEqual(github[3], "github")
        self.assertIn("resolve github", github[github.index("--command") + 1])
        # A second run reuses the stored placeholder (sbx refuses a different one).
        entry.register_secrets(sbx, cfg, bin_path="/home/learner/study-room/bin/study-room")
        second = fake.calls("sbx", "secret", "set-custom")[1]
        self.assertEqual(second[second.index("--placeholder") + 1], "sr-openai-r4nd0m")

    def test_resolver_commands_hold_only_a_path_and_a_name(self) -> None:
        self.assertEqual(resolver_command("/opt/sr/bin/study-room", "openai"), "/opt/sr/bin/study-room resolve openai")
        self.assertEqual(resolver_command("/home/a b/bin/study-room", "github"), "'/home/a b/bin/study-room' resolve github")

    def test_kimi_disabled_by_default_gets_no_secret(self) -> None:
        cfg = self.make_config()
        fake = FakeSbx()
        entry.register_secrets(Sbx(fake.runner, "study-room"), cfg, bin_path="/x/study-room")
        envs = [a[a.index("--env") + 1] for a in fake.calls("sbx", "secret", "set-custom")]
        self.assertEqual(envs, ["OPENAI_API_KEY"])

    def test_only_study_room_is_mounted(self) -> None:
        cfg = self.make_config()
        self.make_vault(cfg)
        fake = FakeSbx()
        sbx = Sbx(fake.runner, "study-room")
        entry.ensure_sandbox(sbx, self.paths, cfg, "study-room/sandbox:abc", say=lambda *_: None)
        create = fake.calls("sbx", "create")[0]
        paths = [a for a in create if a.startswith("/")]
        self.assertEqual(paths, [str(cfg.study_dir)], "exactly one host path: Study Room/")
        self.assertNotIn(str(cfg.vault_path), [a for a in create if a != str(cfg.study_dir)])
        self.assertNotIn(str(repo_root()), " ".join(create), "the trusted checkout is never mounted")
        self.assertIn("--pull", create)
        self.assertEqual(create[create.index("--pull") + 1], "never")
        self.assertEqual(create[create.index("--skills") + 1], "off")

    def test_recreates_when_the_image_changes_and_keeps_the_vault(self) -> None:
        cfg = self.make_config()
        self.make_vault(cfg)
        note = cfg.study_dir / "keep.md"
        note.write_text("durable")
        fake = FakeSbx()
        sbx = Sbx(fake.runner, "study-room")
        entry.ensure_sandbox(sbx, self.paths, cfg, "study-room/sandbox:one", say=lambda *_: None)
        self.assertEqual(entry.ensure_sandbox(sbx, self.paths, cfg, "study-room/sandbox:one", say=lambda *_: None), "sandbox ready")
        entry.ensure_sandbox(sbx, self.paths, cfg, "study-room/sandbox:two", say=lambda *_: None)
        self.assertEqual(len(fake.calls("sbx", "rm")), 1)
        self.assertEqual(len(fake.calls("sbx", "create")), 2)
        self.assertEqual(note.read_text(), "durable")

    def test_profile_payload_matches_the_sandbox_contract(self) -> None:
        cfg = self.make_config()
        payload = entry.profile_payload(cfg, LOCK, ["Host: test"], ["warning a"])
        self.assertEqual(payload["workspace"], str(cfg.study_dir))
        self.assertEqual(payload["main"]["pi_provider"], "openai")
        self.assertEqual(payload["main"]["thinking"], "max")
        self.assertEqual(payload["researcher"]["thinking"], "medium")
        self.assertEqual(payload["researcher"]["model"], "gpt-teach", "researcher follows the main model by default")
        self.assertEqual(payload["network_mode"], "balanced")
        text = json.dumps(payload)
        self.assertNotIn("resolve", text)
        import os
        import tempfile

        node = os.environ.get("STUDY_ROOM_NODE", "node")
        try:
            feature = subprocess.run([node, "-p", "process.features.typescript || ''"], capture_output=True, text=True, timeout=30).stdout.strip()
        except FileNotFoundError:
            feature = ""
        if feature not in ("strip", "transform"):
            self.skipTest("no Node with TypeScript support on this host; set STUDY_ROOM_NODE (the sandbox suite validates profiles too)")
        with tempfile.TemporaryDirectory() as tmp:
            script = Path(tmp) / "check.ts"
            script.write_text(
                f"import {{ validateProfile }} from {json.dumps(str(repo_root() / 'sandbox' / 'lib' / 'profile.ts'))};\n"
                f"validateProfile(JSON.parse({json.dumps(text)}));\nconsole.log('valid');\n"
            )
            out = subprocess.run([node, str(script)], capture_output=True, text=True, timeout=60)
        self.assertEqual(out.stdout.strip(), "valid", out.stderr)

    def test_preflight_refuses_incomplete_configuration(self) -> None:
        cfg = self.make_config(**{"profiles.main.model": None})
        with self.assertRaises(StudyRoomError) as ctx:
            entry.preflight(cfg, LOCK, git_runner())
        self.assertIn("study-room models openai", ctx.exception.hint or "")
        cfg = self.make_config()
        with self.assertRaises(StudyRoomError) as ctx:
            entry.preflight(cfg, LOCK, git_runner())
        self.assertEqual(ctx.exception.failure, Failure.VAULT_PATH_MISSING)

    def test_host_summary(self) -> None:
        f = detect(FixtureProbe(host_fixture("wsl2-ready")))
        lines = entry.host_summary(f, "Obsidian: ok")
        self.assertIn("WSL2", lines[0])
        self.assertIn("WSLg", lines[0])


class UpdateTests(TempHome):
    def results(self, latest: str):
        return [updates.Drift("pi-web-search", "1.6.0", latest, latest != "1.6.0")]

    def test_cache_is_used_within_the_interval_and_never_blocks(self) -> None:
        calls: list[int] = []

        def refresh():
            calls.append(1)
            return self.results("1.7.0")

        first, _ = updates.cached(self.paths, LOCK, 24, refresh, now=1000)
        second, _ = updates.cached(self.paths, LOCK, 24, refresh, now=1000 + 3600)
        self.assertEqual(len(calls), 1)
        self.assertEqual(first, second)
        third, _ = updates.cached(self.paths, LOCK, 24, lambda: (_ for _ in ()).throw(OSError("offline")), now=1000 + 25 * 3600)
        self.assertEqual(third, first, "an unreachable update service keeps the cached answer")
        self.assertEqual(updates.read_cache(self.paths, LOCK, 24, now=1000 + 25 * 3600)[1], False)

    def test_banner_reports_stale_pins_without_installing(self) -> None:
        lines = updates.banner_lines(self.results("1.7.0"))
        self.assertIn("pi-web-search 1.6.0→1.7.0", lines[0])
        self.assertIn("not installed", lines[0])
        self.assertEqual(updates.banner_lines(self.results("1.6.0")), [])

    def test_check_handles_failures_per_dependency(self) -> None:
        from studyroom.http import Client, FakeTransport, json_response

        t = FakeTransport()
        t.on("GET", "https://registry.npmjs.org/", json_response({"version": "9.9.9"}))
        t.on("GET", "https://nodejs.org/dist/index.json", json_response([{"version": "v22.30.0"}, {"version": "v24.1.0"}]))
        runner = FakeRunner().on(["git", "ls-remote"], "0123456789abcdef0123456789abcdef01234567\tHEAD\n")
        results = {r.dependency: r for r in updates.check(LOCK, Client(t), runner)}
        self.assertTrue(results["pi-web-search"].stale)
        self.assertEqual(results["node"].latest, "22.30.0", "the 22.x line is tracked")
        self.assertIsNotNone(results["docker-sbx"].error, "an unreachable source is reported, not fatal")
        self.assertTrue(results["learn"].stale)


class ReceiptsAndVerifyTests(TempHome):
    def pinned_lock(self) -> lockmod.Lock:
        data = json.loads(json.dumps(LOCK.data))
        data["verification"]["openai"]["status"] = "pinned"
        data["verification"]["openai"]["model"] = "gpt-cheap"
        return lockmod.Lock(data, LOCK.path)

    def test_receipts_are_non_secret_and_drive_warnings(self) -> None:
        cfg = self.make_config()
        self.assertIn("never been verified", receipts.warnings(cfg, LOCK, "openai")[0])
        path = receipts.write(cfg, LOCK, "openai", "gpt-cheap", {"provider": "passed", "research": "skipped"}, now=time.time())
        data = json.loads(path.read_text())
        self.assertEqual(set(data) >= {"time", "installation_id", "config_fingerprint", "lock_fingerprint", "provider", "verification_model", "vault_identity", "checks"}, True)
        self.assertNotIn(str(cfg.vault_path), path.read_text(), "the vault is identified by a hash")
        self.assertEqual(receipts.warnings(cfg, LOCK, "openai"), [])
        self.assertTrue(receipts.verified(cfg, LOCK, "openai"))
        cfg.set("profiles.main.model", "gpt-other")
        self.assertTrue(any("configuration changed" in w for w in receipts.warnings(cfg, LOCK, "openai")))
        self.assertTrue(any("pins changed" in w for w in receipts.warnings(cfg, self.pinned_lock(), "openai")))

    def test_candidate_verification_model_cannot_run(self) -> None:
        cfg = self.make_config()
        with self.assertRaises(StudyRoomError) as ctx:
            verify.spec_for(LOCK, cfg, "openai")
        self.assertIn("study-room models openai", ctx.exception.hint or "")

    def test_verification_never_uses_the_teaching_model(self) -> None:
        cfg = self.make_config(**{"profiles.main.model": "gpt-cheap"})
        with self.assertRaises(StudyRoomError):
            verify.spec_for(self.pinned_lock(), cfg, "openai")

    def test_disclosure_names_model_thinking_limits_search_and_timeout(self) -> None:
        cfg = self.make_config()
        spec = verify.spec_for(self.pinned_lock(), cfg, "openai")
        text = "\n".join(verify.disclosure(spec, ["provider", "research"]))
        for needle in ("openai/gpt-cheap", "thinking low", "at most 1 request", "64 output tokens", "timeout 60s", "no search", "1 web_search", "teaching or research quality"):
            self.assertIn(needle, text)

    def test_nothing_is_sent_without_consent(self) -> None:
        cfg = self.make_config()
        fake = FakeSbx()
        with self.assertRaises(StudyRoomError) as ctx:
            verify.run(cfg, self.pinned_lock(), Sbx(fake.runner, "study-room"), "openai", ["provider"], confirm=lambda lines: False, say=lambda *_: None)
        self.assertEqual(ctx.exception.failure, Failure.PERMISSION_DECLINED)
        self.assertEqual(fake.calls("sbx", "exec"), [])

    def test_consented_run_executes_in_the_sandbox_and_writes_a_receipt(self) -> None:
        cfg = self.make_config()
        fake = FakeSbx()
        fake.sandboxes.append({"name": "study-room"})
        fake.runner.on(["sbx", "exec"], lambda argv, _i: Result(argv, 0, json.dumps({"check": argv[-1], "status": "passed", "detail": "ok"})))
        out = verify.run(cfg, self.pinned_lock(), Sbx(fake.runner, "study-room"), "openai", ["provider"], confirm=lambda lines: True, say=lambda *_: None)
        self.assertEqual(out, {"placeholder": "passed", "provider": "passed"})
        exec_call, exec_input = next((a, i) for a, i in fake.runner.calls if a[:2] == ["sbx", "exec"])
        spec = json.loads(exec_input)
        self.assertEqual((spec["model"], spec["thinking"], spec["limits"]["max_requests"]), ("gpt-cheap", "low", 1))
        self.assertIsNotNone(receipts.latest(cfg, "openai"))


class ObsidianTests(TempHome):
    def test_checksum_mismatch_installs_nothing(self) -> None:
        pin = dict(LOCK["obsidian_desktop"])
        body = b"not the pinned artifact"

        class Resp(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False

        with self.assertRaises(StudyRoomError) as ctx:
            obsidian.download(self.paths, pin, opener=lambda url, timeout: Resp(body), say=lambda *_: None)
        self.assertEqual(ctx.exception.failure, Failure.PIN_MISMATCH)
        self.assertFalse(obsidian.deb_path(self.paths, pin).exists())
        self.assertEqual(list(obsidian.deb_path(self.paths, pin).parent.glob("*")), [])

    def test_vault_status(self) -> None:
        cfg = self.make_config()
        st = obsidian.vault_status(cfg, git_runner(), home=self.home)
        self.assertFalse(st.ok)
        self.make_vault(cfg, opened=False, study=False)
        st = obsidian.vault_status(cfg, git_runner(), home=self.home)
        self.assertTrue(any("not been opened" in p for p in st.problems))
        self.make_vault(cfg)
        st = obsidian.vault_status(cfg, git_runner(), home=self.home)
        self.assertTrue(st.ok, st.problems)
        (cfg.study_dir / ".git").mkdir()
        st = obsidian.vault_status(cfg, git_runner(), home=self.home)
        self.assertTrue(any("Git" in p for p in st.problems))

    def test_windows_vault_paths_are_refused(self) -> None:
        cfg = self.make_config(**{"vault.path": "/mnt/c/Users/learner/Vault"})
        st = obsidian.vault_status(cfg, git_runner(), home=self.home)
        self.assertTrue(any("Windows drive" in p for p in st.problems))

    def test_healthy_obsidian_is_not_restarted(self) -> None:
        cfg = self.make_config()
        runner = FakeRunner().on(["pgrep"], "4242\n")
        self.assertIn("already running", obsidian.start_or_reuse(cfg, runner))
        self.assertEqual(runner.detached_calls, [])

    def test_open_uri_targets_the_configured_vault(self) -> None:
        self.assertEqual(obsidian.open_uri(Path("/home/a/Vault Name")), "obsidian://open?path=%2Fhome%2Fa%2FVault%20Name")


class DestroyTests(TempHome):
    def ctx(self, fake: FakeSbx) -> cli.Context:
        c = cli.Context(fake.runner, env=self.env)
        c._config = self.make_config()
        return c

    def test_destroy_removes_only_the_sandbox(self) -> None:
        fake = FakeSbx()
        fake.sandboxes.append({"name": "study-room"})
        c = self.ctx(fake)
        self.make_vault(c._config)
        (c._config.study_dir / "note.md").write_text("keep me")
        with redirect_stdout(io.StringIO()):
            code = cli.main(["destroy", "--yes"], ctx=c)
        self.assertEqual(code, 0)
        self.assertEqual(fake.sandboxes, [])
        self.assertEqual((c._config.study_dir / "note.md").read_text(), "keep me")
        self.assertTrue(self.paths.config_file.exists(), "trusted configuration is kept by default")

    def test_purge_never_runs_without_typed_confirmation(self) -> None:
        fake = FakeSbx()
        c = self.ctx(fake)
        with redirect_stdout(io.StringIO()):
            cli.main(["destroy", "--yes", "--purge-host-state"], ctx=c)
        self.assertTrue(self.paths.config_file.exists())


class BumpTests(TempHome):
    def test_bumps_only_happen_on_a_topic_branch_of_a_clean_checkout(self) -> None:
        main = FakeRunner().on(["git", "-C", str(repo_root()), "rev-parse"], "main\n").on(["git", "-C", str(repo_root()), "symbolic-ref"], "origin/main\n")
        with self.assertRaises(StudyRoomError):
            bump.require_branch(main, repo_root())
        dirty = (
            FakeRunner()
            .on(["git", "-C", str(repo_root()), "rev-parse"], "bump/pi\n")
            .on(["git", "-C", str(repo_root()), "symbolic-ref"], "origin/main\n")
            .on(["git", "-C", str(repo_root()), "status"], " M lock/study-room.lock.json\n")
        )
        with self.assertRaises(StudyRoomError):
            bump.require_branch(dirty, repo_root())

    def test_npm_bump_takes_integrity_from_the_registry(self) -> None:
        from studyroom.http import Client, FakeTransport, json_response

        integrity = "sha512-" + "B" * 86 + "=="
        t = FakeTransport().on(
            "GET",
            "https://registry.npmjs.org/pi-web-search",
            json_response({"dist-tags": {"latest": "1.7.0"}, "versions": {"1.7.0": {"dist": {"tarball": "https://registry.npmjs.org/pi-web-search/-/pi-web-search-1.7.0.tgz", "integrity": integrity}, "license": "MIT", "gitHead": "abc"}}}),
        )
        plan = bump.plan_npm(LOCK, Client(t), "pi-web-search", None)
        data = json.loads(json.dumps(LOCK.data))
        plan.apply(data)
        self.assertEqual(data["npm"]["packages"]["pi-web-search"]["integrity"], integrity)
        self.assertTrue(plan.npm_changed)
        self.assertTrue(any("tarball" in p for p in plan.provenance))

    def test_verification_model_pin(self) -> None:
        plan = bump.plan_verification_model(LOCK, "openai", "gpt-cheap")
        data = json.loads(json.dumps(LOCK.data))
        plan.apply(data)
        self.assertEqual((data["verification"]["openai"]["model"], data["verification"]["openai"]["status"]), ("gpt-cheap", "pinned"))


class RepositoryHygieneTests(TempHome):
    def test_no_credentials_are_committed(self) -> None:
        import re

        # Credential shapes, not field names: code legitimately says `refresh=refresh`.
        shapes = [
            re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"),
            re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"),
            re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
            re.compile(r"\bsk-(?:proj-|ant-)?[A-Za-z0-9_-]{20,}\b"),
            re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
            re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        ]
        files = subprocess.run(["git", "-C", str(repo_root()), "ls-files", "--cached", "--others", "--exclude-standard"], capture_output=True, text=True).stdout.split()
        offenders = []
        for rel in files:
            path = repo_root() / rel
            if not path.is_file() or path.suffix in (".png", ".deb", ".tgz"):
                continue
            for line in path.read_text(errors="ignore").splitlines():
                if "FAKE" in line:
                    continue
                if any(p.search(line) for p in shapes):
                    offenders.append(f"{rel}: {line.strip()[:80]}")
        self.assertEqual(offenders, [])

    def test_gitignore_excludes_state_and_artifacts(self) -> None:
        text = (repo_root() / ".gitignore").read_text()
        for pattern in ("node_modules", "*.jsonl", ".env", "obsidian-vault/"):
            self.assertIn(pattern, text)


class EgressProbeTests(TempHome):
    def test_a_global_allow_all_is_detected(self) -> None:
        fake = FakeSbx()
        fake.runner.on(["sbx", "policy", "check"], Result([], 0, "Allowed: study-room-egress-probe.example:443\n"))
        self.assertTrue(network.wider_than_balanced(Sbx(fake.runner, "study-room")))
        fake.runner.on(["sbx", "policy", "check"], Result([], 1, "Denied: study-room-egress-probe.example:443\nReason: no matching allow rule\n"))
        self.assertFalse(network.wider_than_balanced(Sbx(fake.runner, "study-room")))


class RunOrchestrationTests(TempHome):
    """`study-room run` end to end with fake sbx, docker and Obsidian (no real host changes)."""

    def test_run_prepares_the_sandbox_in_order_and_attaches(self) -> None:
        from studyroom import image

        cfg = self.make_config()
        self.make_vault(cfg)
        fake = FakeSbx()
        tag = image.image_tag(LOCK)
        fake.runner.available |= {"docker"}
        fake.runner.on(["sbx", "template", "ls"], lambda argv, _i: Result(argv, 0, f"NAME\n{tag}\n"))
        fake.runner.on(["sbx", "exec"], lambda argv, _i: Result(argv, 0, "study-room-configure: ok\n"))
        fake.runner.on(["sbx", "policy", "check"], Result([], 1, "Denied: x\n"))
        fake.runner.on(["git"], Result([], 128, "", "not a repo"))
        fake.runner.on(["pgrep"], "4242\n")  # Obsidian already running: reused, not restarted
        facts = detect(FixtureProbe(host_fixture("wsl2-ready")))
        out: list[str] = []
        code = entry.run(cfg, LOCK, fake.runner, facts, egress_check=lambda: [], say=out.append)
        self.assertEqual(code, 0)
        seq = [" ".join(a[:3]) for a in fake.runner.argvs() if a[0] == "sbx"]
        first = lambda prefix: next(i for i, s in enumerate(seq) if s.startswith(prefix))
        self.assertLess(first("sbx secret set-custom"), first("sbx create"), "placeholders exist before the sandbox is created")
        self.assertLess(first("sbx create"), first("sbx policy deny"))
        self.assertLess(first("sbx policy allow"), first("sbx exec"), "rules are in place before entry")
        configure = next((a, i) for a, i in fake.runner.calls if a[:2] == ["sbx", "exec"] and "-u" in a)
        self.assertEqual(configure[0][configure[0].index("-u") + 1], "root")
        payload = json.loads(configure[1])
        self.assertEqual(payload["workspace"], str(cfg.study_dir))
        self.assertEqual(fake.runner.interactive_calls[-1], ["sbx", "exec", "-it", "study-room", "/opt/study-room/bin/study-room-entry"])
        self.assertFalse(any(a[:2] == ["docker", "build"] for a in fake.runner.interactive_calls), "a loaded template is reused")
        self.assertIn("already running", payload["host_summary"][1], "a healthy Obsidian is reused, not restarted")
        self.assertEqual(fake.runner.detached_calls, [])

    def test_global_allow_all_is_flagged_in_the_banner(self) -> None:
        from studyroom import image

        cfg = self.make_config()
        self.make_vault(cfg)
        fake = FakeSbx()
        tag = image.image_tag(LOCK)
        fake.runner.on(["sbx", "template", "ls"], lambda argv, _i: Result(argv, 0, f"{tag}\n"))
        fake.runner.on(["sbx", "policy", "check"], Result([], 0, "Allowed: study-room-egress-probe.example:443\n"))
        fake.runner.on(["git"], Result([], 128, "", ""))
        fake.runner.on(["pgrep"], "1\n")
        entry.run(cfg, LOCK, fake.runner, detect(FixtureProbe(host_fixture("wsl2-ready"))), egress_check=lambda: [], say=lambda *_: None)
        configure = next(i for a, i in fake.runner.calls if a[:2] == ["sbx", "exec"] and "-u" in a)
        self.assertTrue(any("wider than intended" in w for w in json.loads(configure)["warnings"]))


class DoctorTests(TempHome):
    def test_doctor_reports_without_secrets(self) -> None:
        from studyroom import doctor
        from studyroom.keyring import Keyring

        cfg = self.make_config()
        self.make_vault(cfg)
        kr_runner = FakeRunner(available={"secret-tool", "busctl"}).on(["busctl"], 'aoao 1 "/x/1" 0').on(["git"], Result([], 128, "", ""))
        findings = doctor.host_findings(detect(FixtureProbe(host_fixture("wsl2-ready"))), LOCK)
        findings += doctor.config_findings(cfg, LOCK, kr_runner, Keyring(kr_runner))
        lines = doctor.render(findings)
        self.assertTrue(any("sbx 0.46.0 (pinned 0.46.0)" in l for l in lines))
        self.assertTrue(any(l.startswith("ok   infisical handles") for l in lines))
        self.assertTrue(any("never been verified" in l for l in lines))
        self.assertFalse(any(a[:2] == ["secret-tool", "lookup"] for a in kr_runner.argvs()), "doctor never reads secret values")
        self.assertEqual(doctor.exit_code(findings), 0, "a ready host with only unverified live checks is not a failure")
