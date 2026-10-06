"""Functional test of the egress guard on the real kernel netfilter (decision 2).

Runs tests/egress/functional.sh as root in a disposable privileged container
with its own network namespace, so the machine's real firewall is never
touched. Skipped, with the reason, where Docker cannot run such a container
or the kernel lacks the xtables cgroup match.
"""

from __future__ import annotations

import shutil
import subprocess
import unittest

from studyroom.paths import repo_root

IMAGE = "ubuntu:24.04"
PACKAGES = "iptables iproute2 python3 curl procps"


def _docker_privileged() -> str | None:
    if shutil.which("docker") is None:
        return "Docker is not installed"
    probe = subprocess.run(
        ["docker", "run", "--rm", "--privileged", "--cgroupns=host", IMAGE, "sh", "-c", "test -f /sys/fs/cgroup/cgroup.controllers"],
        capture_output=True, text=True, timeout=300,
    )
    if probe.returncode != 0:
        return f"cannot run a privileged container with cgroup v2 here: {(probe.stderr or probe.stdout).strip()[:120]}"
    return None


class EgressGuardFunctionalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        reason = _docker_privileged()
        if reason:
            raise unittest.SkipTest(reason)

    def test_guard_on_real_netfilter(self) -> None:
        root = repo_root()
        script = (
            "set -e; apt-get update -qq >/dev/null; "
            f"DEBIAN_FRONTEND=noninteractive apt-get install -y -qq {PACKAGES} >/dev/null 2>&1; "
            "iptables -m cgroup --help >/dev/null 2>&1 || { echo 'SKIP: no xtables cgroup match'; exit 77; }; "
            "bash /src/tests/egress/functional.sh /src/host/sbx-egress-guard"
        )
        res = subprocess.run(
            ["docker", "run", "--rm", "--privileged", "--cgroupns=host", "-v", f"{root}:/src:ro", IMAGE, "bash", "-c", script],
            capture_output=True, text=True, timeout=900,
        )
        if res.returncode == 77:
            self.skipTest("the kernel has no xtables cgroup match")
        output = res.stdout + res.stderr
        self.assertNotIn("FAIL", output, output)
        self.assertEqual(res.returncode, 0, output)
        self.assertIn("# result: 0 failure(s)", output)


if __name__ == "__main__":
    unittest.main()
