"""Host capability fixtures and installer planning (SPEC 5, 16.1, 20.1)."""

from __future__ import annotations

from studyroom import hostdetect
from studyroom import lock as lockmod
from studyroom import setup as setupmod
from studyroom.errors import Failure, StudyRoomError
from studyroom.runner import FakeRunner

from tests.host.helpers import TempHome, host_fixture

LOCK = lockmod.load()
HOST_PKGS = [p["name"] for p in LOCK["system_packages"]["host"]]


def facts(name: str) -> hostdetect.HostFacts:
    return hostdetect.detect(hostdetect.FixtureProbe(host_fixture(name)))


def nothing_installed() -> dict:
    return {n: None for n in HOST_PKGS}


def everything_installed() -> dict:
    out = {n: "99.0" for n in HOST_PKGS}
    out["docker-sbx"] = "0.46.0-1~ubuntu.24.04~noble"
    return out


class DetectionTests(TempHome):
    def test_native_desktop(self) -> None:
        f = facts("native-ubuntu-24.04")
        self.assertEqual((f.os_id, f.os_version, f.machine), ("ubuntu", "24.04", "x86_64"))
        self.assertFalse(f.wsl2)
        self.assertEqual(f.display_kind, "wayland")
        self.assertTrue(f.systemd_system and f.systemd_user)
        self.assertTrue(f.kvm_device)
        self.assertFalse(f.kvm_accessible)
        self.assertTrue(f.secret_service)

    def test_wsl2_detected_by_capability(self) -> None:
        f = facts("wsl2-ubuntu-24.04")
        self.assertTrue(f.wsl2)
        self.assertEqual(f.display_kind, "wslg", "WSLg is a capability (sockets under /mnt/wslg), not a platform branch")
        self.assertTrue(f.kvm_accessible)

    def test_wsl_kernel_without_wslg_uses_the_session_display(self) -> None:
        fx = host_fixture("wsl2-ubuntu-24.04")
        fx["paths"].remove("/mnt/wslg")
        f = hostdetect.detect(hostdetect.FixtureProbe(fx))
        self.assertEqual(f.display_kind, "wayland")

    def test_ready_host(self) -> None:
        f = facts("wsl2-ready")
        self.assertEqual(f.sbx_version, "0.46.0")
        self.assertTrue(f.sbx_logged_in)
        self.assertTrue(f.sbx_policy_initialized)
        self.assertEqual(f.obsidian_installed_version, "1.14.4")


class PlanTests(TempHome):
    def plan(self, name: str, installed: dict, **kw) -> setupmod.Plan:
        return setupmod.build_plan(
            facts(name), LOCK, self.paths, installed, sbx_apt_version=kw.get("sbx_apt_version", "0.46.0-1~ubuntu.24.04~noble"), docker_repo_configured=kw.get("repo", False)
        )

    def test_fresh_native_host_proposes_everything_with_sudo_shown(self) -> None:
        plan = self.plan("native-ubuntu-24.04", nothing_installed())
        self.assertEqual(plan.blockers, [])
        keys = [c.key for c in plan.changes]
        self.assertEqual(keys, ["packages", "docker-repo", "docker", "kvm-group", "docker-group", "obsidian"])
        rendered = "\n".join(setupmod.render(plan))
        self.assertIn("nothing has been changed yet", rendered)
        self.assertIn("sudo usermod -aG kvm learner", rendered)
        self.assertIn("docker-sbx=0.46.0-1~ubuntu.24.04~noble", rendered)
        self.assertIn("obsidian_1.14.4_amd64.deb", rendered)
        self.assertIn("log out and back in", rendered)
        docker_group = next(c for c in plan.changes if c.key == "docker-group")
        self.assertTrue(docker_group.optional)
        self.assertIn("root", docker_group.reason)

    def test_wsl2_host_skips_the_kvm_group_it_already_has(self) -> None:
        plan = self.plan("wsl2-ubuntu-24.04", nothing_installed())
        self.assertNotIn("kvm-group", [c.key for c in plan.changes])

    def test_unsupported_hosts_are_blocked_before_any_change(self) -> None:
        cases = {
            "headless-server": Failure.UNSUPPORTED_PLATFORM,
            "arm64-desktop": Failure.UNSUPPORTED_PLATFORM,
            "ubuntu-22.04-desktop": Failure.UNSUPPORTED_PLATFORM,
            "wsl2-no-kvm-no-systemd": Failure.MISSING_PREREQUISITE,
        }
        for name, failure in cases.items():
            plan = self.plan(name, nothing_installed())
            self.assertTrue(plan.blockers, name)
            self.assertIn(failure, [b.failure for b in plan.blockers], name)
            runner = FakeRunner()
            with self.assertRaises(StudyRoomError):
                setupmod.apply(plan, runner, lambda c: True)
            self.assertEqual(runner.interactive_calls, [], f"{name}: nothing ran")
        no_kvm = self.plan("wsl2-no-kvm-no-systemd", nothing_installed())
        hints = " ".join(b.hint for b in no_kvm.blockers)
        self.assertIn("wsl.conf", hints)
        self.assertIn("nested virtualization", hints)

    def test_setup_is_idempotent_on_a_ready_host(self) -> None:
        plan = self.plan("wsl2-ready", everything_installed(), repo=True)
        self.assertTrue(plan.empty, setupmod.render(plan))
        self.assertIn("No host changes are needed.", setupmod.render(plan))

    def test_never_substitutes_an_unpinned_docker_sbx(self) -> None:
        installed = everything_installed()
        installed["docker-sbx"] = None
        plan = self.plan("wsl2-ready", installed, repo=True, sbx_apt_version=None)
        self.assertIn(Failure.PIN_MISMATCH, [b.failure for b in plan.blockers])
        self.assertNotIn("docker", [c.key for c in plan.changes])

    def test_wrong_sbx_version_is_replaced_with_the_pin(self) -> None:
        installed = everything_installed()
        installed["docker-sbx"] = "0.47.0-1~ubuntu.24.04~noble"
        plan = self.plan("wsl2-ready", installed, repo=True)
        change = next(c for c in plan.changes if c.key == "docker")
        self.assertIn("docker-sbx=0.46.0-1~ubuntu.24.04~noble", change.commands[0])
        self.assertIn("replacing docker-sbx 0.47.0", change.title)

    def test_policy_init_only_when_uninitialized(self) -> None:
        fx = host_fixture("wsl2-ready")
        fx["commands_output"]["sbx policy ls"] = {"rc": 1, "stderr": "policy not initialized: run sbx policy init"}
        f = hostdetect.detect(hostdetect.FixtureProbe(fx))
        plan = setupmod.build_plan(f, LOCK, self.paths, everything_installed(), sbx_apt_version="0.46.0-1", docker_repo_configured=True)
        self.assertEqual([c.key for c in plan.changes], ["sbx-policy"])
        self.assertEqual(plan.changes[0].commands, [["sbx", "policy", "init", "balanced"]])
        initialized = self.plan("wsl2-ready", everything_installed(), repo=True)
        self.assertNotIn("sbx-policy", [c.key for c in initialized.changes], "an existing policy is never overwritten")


class ApplyTests(TempHome):
    def test_only_approved_changes_run(self) -> None:
        plan = setupmod.build_plan(facts("native-ubuntu-24.04"), LOCK, self.paths, nothing_installed(), sbx_apt_version="0.46.0-1", docker_repo_configured=False)
        runner = FakeRunner()
        approved = {"packages", "docker-repo", "docker", "kvm-group", "obsidian"}
        prepared: list[str] = []
        for change in plan.changes:
            if change.key in ("obsidian", "docker-repo"):
                change.prepare = lambda k=change.key: prepared.append(k)
        afters = setupmod.apply(plan, runner, lambda c: c.key in approved, say=lambda *_: None)
        ran = [" ".join(a) for a in runner.interactive_calls]
        self.assertFalse(any("usermod -aG docker" in r for r in ran), "the declined optional change did not run")
        self.assertTrue(any("usermod -aG kvm" in r for r in ran))
        self.assertEqual(prepared, ["docker-repo", "obsidian"], "downloads are verified before the sudo install")
        self.assertTrue(any("kvm" in a for a in afters))

    def test_declining_a_required_change_stops_without_running_later_ones(self) -> None:
        plan = setupmod.build_plan(facts("native-ubuntu-24.04"), LOCK, self.paths, nothing_installed(), sbx_apt_version="0.46.0-1", docker_repo_configured=False)
        runner = FakeRunner()
        with self.assertRaises(StudyRoomError) as ctx:
            setupmod.apply(plan, runner, lambda c: c.key != "packages", say=lambda *_: None)
        self.assertEqual(ctx.exception.failure, Failure.PERMISSION_DECLINED)
        self.assertEqual(runner.interactive_calls, [])

    def test_failed_command_stops_setup(self) -> None:
        plan = setupmod.build_plan(facts("native-ubuntu-24.04"), LOCK, self.paths, nothing_installed(), sbx_apt_version="0.46.0-1", docker_repo_configured=False)
        runner = FakeRunner().on(["sudo", "apt-get", "update"], 100)
        with self.assertRaises(StudyRoomError):
            setupmod.apply(plan, runner, lambda c: True, say=lambda *_: None)
        self.assertEqual(len(runner.interactive_calls), 1)

    def test_docker_repository_lines_are_pinned(self) -> None:
        cmds = setupmod.docker_repo_commands(LOCK, self.paths.downloads_dir / "docker.asc")
        text = " ".join(" ".join(c) for c in cmds)
        self.assertIn("signed-by=/etc/apt/keyrings/docker.asc", text)
        self.assertIn("https://download.docker.com/linux/ubuntu noble stable", text)

    def test_key_fingerprint_is_verified(self) -> None:
        good = "9DC858229FC7DD38854AE2D88D81803C0EBFCD88"
        runner = FakeRunner().on(["gpg"], f"pub:-:4096:1:8D81803C0EBFCD88:1487788586:::-:::scESA::::::23::0:\nfpr:::::::::{good}:\n")
        setupmod.verify_key_fingerprint(runner, self.paths.downloads_dir / "k", good)
        bad = FakeRunner().on(["gpg"], "fpr:::::::::0000000000000000000000000000000000000000:\n")
        with self.assertRaises(StudyRoomError) as ctx:
            setupmod.verify_key_fingerprint(bad, self.paths.downloads_dir / "k", good)
        self.assertEqual(ctx.exception.failure, Failure.PIN_MISMATCH)

    def test_sbx_candidate_version_matches_only_the_pin(self) -> None:
        out = " docker-sbx | 0.47.0-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable amd64 Packages\n" \
              " docker-sbx | 0.46.0-1~ubuntu.24.04~noble | https://download.docker.com/linux/ubuntu noble/stable amd64 Packages\n"
        runner = FakeRunner().on(["apt-cache", "madison", "docker-sbx"], out)
        self.assertEqual(setupmod.sbx_candidate_version(runner, "0.46.0"), "0.46.0-1~ubuntu.24.04~noble")
        self.assertIsNone(setupmod.sbx_candidate_version(runner, "0.45.9"))
