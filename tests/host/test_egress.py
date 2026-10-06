"""Egress guard for the Docker Sandboxes daemon (decision 2): unit, sudoers, checks, setup, live verification."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

from studyroom import egress, entry
from studyroom import lock as lockmod
from studyroom import setup as setupmod
from studyroom.errors import Failure, StudyRoomError
from studyroom.hostdetect import FixtureProbe, detect
from studyroom.paths import repo_root
from studyroom.runner import FakeRunner, Result

from tests.host.helpers import TempHome, host_fixture

LOCK = lockmod.load()
UNIT_CGROUP = "user.slice/user-1000.slice/user@1000.service/study-room.slice/study-room-sbx.service"


class RulesTests(TempHome):
    def test_the_guard_script_parses(self) -> None:
        res = subprocess.run(["bash", "-n", str(egress.guard_source())], capture_output=True, text=True)
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertTrue(os.access(egress.guard_source(), os.X_OK))

    def test_cgroup_path_of_the_managed_unit(self) -> None:
        self.assertEqual(egress.cgroup_path(1000), UNIT_CGROUP)


class UnitAndSudoersTests(TempHome):
    def test_unit_loads_the_guard_before_the_daemon_and_unloads_after(self) -> None:
        unit = egress.render_unit(sbx_bin="/usr/bin/sbx")
        lines = [l.strip() for l in unit.splitlines()]
        self.assertIn("Slice=study-room.slice", lines)
        self.assertIn(f"ExecStartPre=/usr/bin/sudo -n {egress.GUARD_INSTALL_PATH} load", lines)
        self.assertIn("ExecStart=/usr/bin/sbx daemon start", lines, "foreground, so the daemon stays in the unit's cgroup")
        self.assertIn(f"ExecStopPost=/usr/bin/sudo -n {egress.GUARD_INSTALL_PATH} unload", lines)
        self.assertIn("Restart=on-failure", lines)
        self.assertIn("WantedBy=default.target", lines)
        self.assertLess(lines.index(f"ExecStartPre=/usr/bin/sudo -n {egress.GUARD_INSTALL_PATH} load"), lines.index("ExecStart=/usr/bin/sbx daemon start"))
        self.assertNotIn("-d", unit.split("ExecStart=")[1].split("\n")[0].split())

    def test_sudoers_allows_exactly_the_guard_actions(self) -> None:
        text = egress.render_sudoers("learner")
        rules = [l for l in text.splitlines() if l and not l.startswith("#")]
        self.assertEqual(
            rules,
            [f"learner ALL=(root) NOPASSWD: {egress.GUARD_INSTALL_PATH} load, {egress.GUARD_INSTALL_PATH} unload, {egress.GUARD_INSTALL_PATH} status"],
        )
        self.assertNotIn("*", rules[0])
        for bad in ("root", "a b", "x,ALL", "../x", ""):
            with self.assertRaises(StudyRoomError):
                egress.render_sudoers(bad)


def fake_proc(tmp: Path, processes: dict[int, tuple[list[str], str]]) -> Path:
    proc = tmp / "proc"
    for pid, (argv, cgroup) in processes.items():
        d = proc / str(pid)
        d.mkdir(parents=True)
        (d / "cmdline").write_bytes(b"\0".join(a.encode() for a in argv) + b"\0")
        (d / "comm").write_text(Path(argv[0]).name[:15] + "\n")
        (d / "cgroup").write_text(f"0::/{cgroup}\n")
    return proc


class CheckTests(TempHome):
    def setUp(self) -> None:
        super().setUp()
        self.cgroot = self.tmp / "cgroup"
        (self.cgroot / UNIT_CGROUP).mkdir(parents=True)
        self.status = self.tmp / "run" / "sbx-egress.json"
        self.status.parent.mkdir()
        self.active = FakeRunner().on(["systemctl", "--user", "is-active", egress.UNIT], "active\n")
        self.active.on(["sudo", "-n", egress.GUARD_INSTALL_PATH, "status"], f"loaded cgroup={UNIT_CGROUP} rejected=0\n")

    def write_status(self, inode: int | None = None) -> None:
        ino = inode if inode is not None else (self.cgroot / UNIT_CGROUP).stat().st_ino
        self.status.write_text(json.dumps({"cgroup": UNIT_CGROUP, "cgroup_inode": ino, "uid": 1000}))

    def check(self, proc: Path, runner=None):
        return egress.check(1000, runner=runner or self.active, proc_root=proc, cgroup_root=self.cgroot, status_file=self.status)

    def codes(self, problems) -> list[str]:
        return [p.code for p in problems]

    def test_healthy(self) -> None:
        proc = fake_proc(self.tmp, {100: (["/usr/bin/sbx", "daemon", "start"], UNIT_CGROUP), 101: (["/usr/bin/sbx", "ls"], "user.slice/user-1000.slice/session-2.scope")})
        self.write_status()
        self.assertEqual(self.check(proc), [])
        self.assertEqual(egress.daemon_pids(proc), [100])

    def test_daemon_started_outside_the_unit_fails_closed(self) -> None:
        proc = fake_proc(self.tmp, {200: (["sbx", "daemon", "start", "-d"], "user.slice/user-1000.slice/session-2.scope")})
        self.write_status()
        self.assertIn("daemon_outside_unit", self.codes(self.check(proc)))

    def test_inactive_unit(self) -> None:
        proc = fake_proc(self.tmp, {})
        runner = FakeRunner().on(["systemctl", "--user", "is-active", egress.UNIT], Result([], 3, "inactive\n"))
        self.assertIn("unit_inactive", self.codes(self.check(proc, runner)))

    def test_guard_not_loaded_or_stale(self) -> None:
        proc = fake_proc(self.tmp, {100: (["/usr/bin/sbx", "daemon", "start"], UNIT_CGROUP)})
        self.assertIn("guard_not_loaded", self.codes(self.check(proc)))
        self.write_status(inode=1)
        self.assertIn("guard_stale", self.codes(self.check(proc)))

    def test_flushed_firewall_rules_are_noticed_despite_the_status_file(self) -> None:
        proc = fake_proc(self.tmp, {100: (["/usr/bin/sbx", "daemon", "start"], UNIT_CGROUP)})
        self.write_status()
        for live in (Result([], 0, "loaded cgroup=none rejected=0\n"), Result([], 3, "not loaded\n"), Result([], 1, "", "sudo: a password is required\n")):
            self.active.on(["sudo", "-n", egress.GUARD_INSTALL_PATH, "status"], live)
            self.assertEqual(self.codes(self.check(proc)), ["guard_not_loaded"], live.stdout or live.stderr)

    def test_rules_loaded_for_another_cgroup_are_not_the_guard(self) -> None:
        proc = fake_proc(self.tmp, {100: (["/usr/bin/sbx", "daemon", "start"], UNIT_CGROUP)})
        self.write_status()
        self.active.on(["sudo", "-n", egress.GUARD_INSTALL_PATH, "status"], "loaded cgroup=user.slice/user-1001.slice/user@1001.service/study-room.slice/study-room-sbx.service rejected=0\n")
        self.assertEqual(self.codes(self.check(proc)), ["guard_not_loaded"])

    def test_no_daemon(self) -> None:
        self.write_status()
        self.assertIn("daemon_not_running", self.codes(self.check(fake_proc(self.tmp, {}))))

    def test_problems_name_the_fix(self) -> None:
        proc = fake_proc(self.tmp, {200: (["sbx", "daemon", "start"], "user.slice/user-1000.slice/session-2.scope")})
        for p in self.check(proc):
            self.assertTrue(p.hint, p.code)


class SetupTests(TempHome):
    STATE_MISSING = egress.InstallState(guard_ok=False, sudoers_ok=False, unit_ok=False, enabled=False)
    STATE_READY = egress.InstallState(guard_ok=True, sudoers_ok=True, unit_ok=True, enabled=True)

    def plan(self, state: egress.InstallState) -> setupmod.Plan:
        facts = detect(FixtureProbe(host_fixture("wsl2-ready")))
        installed = {p["name"]: "99" for p in LOCK["system_packages"]["host"]}
        installed["docker-sbx"] = "0.46.0-1"
        return setupmod.build_plan(facts, LOCK, self.paths, installed, sbx_apt_version="0.46.0-1", docker_repo_configured=True, egress_state=state, egress_user="learner", egress_uid=1000)

    def test_missing_guard_is_a_shown_and_approved_change(self) -> None:
        plan = self.plan(self.STATE_MISSING)
        change = next(c for c in plan.changes if c.key == "egress-guard")
        self.assertEqual(change.category, "firewall")
        text = "\n".join(change.render())
        self.assertIn(f"sudo install -D -m 0755 -o root -g root {egress.guard_source()} {egress.GUARD_INSTALL_PATH}", text)
        self.assertIn("visudo -cf", text)
        self.assertIn(egress.SUDOERS_PATH, text)
        self.assertIn("systemctl --user enable --now study-room-sbx.service", text)
        self.assertIn("every Docker Sandbox", change.reason)

    def test_installed_guard_needs_no_change(self) -> None:
        self.assertNotIn("egress-guard", [c.key for c in self.plan(self.STATE_READY).changes])

    def test_iptables_is_a_host_package(self) -> None:
        self.assertIn("iptables", [p["name"] for p in LOCK["system_packages"]["host"]])

    def test_install_state_detects_drift(self) -> None:
        guard = self.tmp / "guard"
        sudoers = self.tmp / "sudoers"
        unit_dir = self.tmp / "units"
        st = egress.install_state(self.paths, "learner", FakeRunner().on(["systemctl"], Result([], 1, "disabled\n")), sbx_bin="/usr/bin/sbx", guard_path=guard, sudoers_path=sudoers, unit_dir=unit_dir)
        self.assertEqual(st, self.STATE_MISSING)
        guard.write_bytes(egress.guard_source().read_bytes())
        sudoers.write_text(egress.render_sudoers("learner"))
        unit_dir.mkdir()
        (unit_dir / egress.UNIT).write_text(egress.render_unit(sbx_bin="/usr/bin/sbx"))
        (unit_dir / egress.SLICE).write_text(egress.render_slice())
        st = egress.install_state(self.paths, "learner", FakeRunner().on(["systemctl"], "enabled\n"), sbx_bin="/usr/bin/sbx", guard_path=guard, sudoers_path=sudoers, unit_dir=unit_dir)
        self.assertEqual(st, self.STATE_READY)
        guard.write_text("#!/bin/sh\nexit 0\n")
        st = egress.install_state(self.paths, "learner", FakeRunner().on(["systemctl"], "enabled\n"), sbx_bin="/usr/bin/sbx", guard_path=guard, sudoers_path=sudoers, unit_dir=unit_dir)
        self.assertFalse(st.guard_ok, "a modified guard is reinstalled")


class EntryTests(TempHome):
    def test_run_fails_closed_without_a_healthy_guard(self) -> None:
        cfg = self.make_config()
        self.make_vault(cfg)
        runner = FakeRunner(available={"sbx"})
        runner.on(["git"], Result([], 128, "", ""))
        problem = egress.Problem("daemon_outside_unit", "the Docker Sandboxes daemon runs outside study-room-sbx.service", "systemctl --user restart study-room-sbx.service")
        with self.assertRaises(StudyRoomError) as ctx:
            entry.run(cfg, LOCK, runner, detect(FixtureProbe(host_fixture("wsl2-ready"))), egress_check=lambda: [problem], say=lambda *_: None)
        self.assertEqual(ctx.exception.failure, Failure.MISSING_PREREQUISITE)
        self.assertIn("systemctl --user restart study-room-sbx.service", ctx.exception.hint or "")
        self.assertFalse(any(a[:2] == ["sbx", "create"] for a in runner.argvs()), "nothing starts without the guard")


class LiveVerifyTests(TempHome):
    """`study-room verify --live egress` orchestration, with every side effect faked."""

    def setUp(self) -> None:
        super().setUp()
        self.events: list[str] = []
        self.runner = FakeRunner(available={"sbx", "tailscale"})
        self.runner.on(["sudo"], self._sudo)
        self.runner.on(["sbx", "policy"], self._policy)
        self.runner.on(["sbx", "exec"], self._exec)
        self.runner.on(["tailscale", "status", "--json"], json.dumps({"BackendState": "Running"}))
        self.rejected = 0
        self.proc = fake_proc(
            self.tmp,
            {
                100: (["/usr/bin/sbx", "daemon", "start"], UNIT_CGROUP),
                300: (["/usr/sbin/tailscaled", "--state=/var/lib/tailscale/tailscaled.state"], "system.slice/tailscaled.service"),
                400: (["/usr/bin/docker-proxy", "-proto", "tcp", "-host-ip", "127.0.0.1", "-host-port", "8431"], "system.slice/docker.service"),
            },
        )

    def _sudo(self, argv, _i):
        self.events.append("sudo " + " ".join(argv[1:4]))
        if argv[-1] == "status":
            return Result(argv, 0, f"loaded cgroup={UNIT_CGROUP} rejected={self.rejected}\n")
        return Result(argv, 0, "")

    def _policy(self, argv, _i):
        self.events.append(" ".join(argv[1:4]) + " " + argv[-1])
        return Result(argv, 0, "")

    def _exec(self, argv, _i):
        url = argv[-1]
        if "api.github.com" in url:
            return Result(argv, 0, "200")
        self.rejected += 1
        return Result(argv, 0, "502")

    def verify(self, **kw):
        server = {"started": 0, "stopped": 0}

        class Server:
            def stop(self_inner):
                server["stopped"] += 1

        def start(ip, port):
            server["started"] += 1
            return Server()

        out = egress.live_verify(
            self.runner,
            "study-room",
            uid=1000,
            confirm=kw.get("confirm", lambda lines: True),
            say=lambda *_: None,
            proc_root=self.proc,
            check=kw.get("check", lambda: []),
            http_get=kw.get("http_get", lambda url: 200),
            tcp_connect=kw.get("tcp_connect", lambda host, port: True),
            resolve=kw.get("resolve", lambda name: ["10.213.0.1"]),
            start_server=start,
            tailscale_peer=kw.get("tailscale_peer"),
        )
        return out, server

    def test_full_run(self) -> None:
        out, server = self.verify(tailscale_peer="100.101.102.103:8443")
        self.assertEqual(out["guard"], "passed")
        self.assertEqual(out["host_private"], "passed", "host traffic to a private address is unaffected")
        self.assertEqual(out["sandbox_private_literal"], "passed", "the sandbox cannot reach the private address")
        self.assertEqual(out["sandbox_private_hostname"], "passed", "nor through a public name that resolves to it")
        self.assertEqual(out["sandbox_public"], "passed")
        self.assertEqual(out["tailscale_cgroup"], "passed")
        self.assertEqual(out["tailscale_running"], "passed")
        self.assertEqual(out["tailscale_host_peer"], "passed")
        self.assertEqual(out["sandbox_tailscale_peer"], "passed")
        self.assertEqual(out["hub_cgroup"], "passed")
        self.assertEqual(out["hub_session_port"], "passed")
        allows = [e for e in self.events if e.startswith("policy allow network")]
        removes = [e for e in self.events if e.startswith("policy rm network")]
        self.assertEqual(len(allows), 3)
        self.assertEqual(len(removes), 3, "every temporary allow is removed")
        self.assertEqual((server["started"], server["stopped"]), (1, 1))
        self.assertTrue(any("ip link del" in e for e in self.events), "the dummy interface is removed")

    def test_nothing_happens_without_consent(self) -> None:
        with self.assertRaises(StudyRoomError):
            self.verify(confirm=lambda lines: False)
        self.assertEqual(self.events, [])

    def test_unhealthy_guard_stops_the_check(self) -> None:
        problem = egress.Problem("guard_not_loaded", "x", "y")
        out, server = self.verify(check=lambda: [problem])
        self.assertEqual(out["guard"], "failed")
        self.assertEqual(server["started"], 0)

    def test_a_reachable_private_address_from_the_sandbox_fails_the_check(self) -> None:
        self.runner.on(["sbx", "exec"], lambda argv, _i: Result(argv, 0, "200"))
        out, _ = self.verify()
        self.assertEqual(out["sandbox_private_literal"], "failed")

    def test_a_refusal_by_docker_sandboxes_policy_does_not_count_as_the_guard(self) -> None:
        self.runner.on(["sbx", "exec"], lambda argv, _i: Result(argv, 0, "200" if "api.github.com" in argv[-1] else "403"))
        out, _ = self.verify(tailscale_peer="100.101.102.103:8443")
        self.assertEqual(out["sandbox_private_literal"], "failed")
        self.assertEqual(out["sandbox_private_hostname"], "failed")
        self.assertEqual(out["sandbox_tailscale_peer"], "failed")
        self.assertEqual(out["sandbox_public"], "passed")

    def test_a_failed_exec_does_not_count_as_the_guard(self) -> None:
        def exec_(argv, _i):
            if "api.github.com" in argv[-1]:
                return Result(argv, 0, "200")
            self.rejected += 1
            return Result(argv, 1, "", "sbx: sandbox not running")

        self.runner.on(["sbx", "exec"], exec_)
        out, _ = self.verify()
        self.assertEqual(out["sandbox_private_literal"], "failed")

    def test_each_step_needs_its_own_guard_rejection(self) -> None:
        def exec_(argv, _i):
            if "api.github.com" in argv[-1]:
                return Result(argv, 0, "200")
            if "sslip.io" not in argv[-1]:
                self.rejected += 1
            return Result(argv, 0, "502")

        self.runner.on(["sbx", "exec"], exec_)
        out, _ = self.verify()
        self.assertEqual(out["sandbox_private_literal"], "passed")
        self.assertEqual(out["sandbox_private_hostname"], "failed", "a 502 without a guard rejection is not the guard")

    def test_cleanup_runs_when_a_step_raises(self) -> None:
        def boom(_url):
            raise RuntimeError("network down")

        with self.assertRaises(RuntimeError):
            self.verify(http_get=boom)
        self.assertTrue(any("ip link del" in e for e in self.events))

    def test_tailscale_absent_is_skipped_with_a_reason(self) -> None:
        self.runner.available.discard("tailscale")
        proc = fake_proc(self.tmp / "p2", {100: (["/usr/bin/sbx", "daemon", "start"], UNIT_CGROUP)})
        self.proc = proc
        out, _ = self.verify()
        self.assertEqual(out["tailscale_cgroup"], "skipped")
        self.assertEqual(out["hub_cgroup"], "skipped")

    def test_a_tailscale_process_inside_the_daemon_unit_fails(self) -> None:
        self.proc = fake_proc(self.tmp / "p3", {100: (["/usr/bin/sbx", "daemon", "start"], UNIT_CGROUP), 300: (["tailscaled"], UNIT_CGROUP)})
        out, _ = self.verify()
        self.assertEqual(out["tailscale_cgroup"], "failed")
