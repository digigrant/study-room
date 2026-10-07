"""Sandbox-scoped network modes (SPEC 13).

``balanced`` (default): Docker Sandboxes' balanced baseline plus the explicit
provider, GitHub and package-registry destinations Study Room needs.

``web``: balanced plus arbitrary public HTTP(S) on TCP 80 and 443 for this
sandbox only. Docker Sandboxes applies one policy to the whole sandbox, so
the teacher, the researcher and every shell command get the same egress.

Both modes deny loopback, host-gateway, link-local, metadata and private
destinations for this sandbox. Docker Sandboxes does not apply CIDR denies
to host names, so these denies stop literal internal addresses and named
internal hosts; see docs/SECURITY.md for the residual DNS-rebinding risk in
``web`` mode.

Study Room records the rules it added, so a mode change removes only its own
rules and never touches global policy.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import fsutil
from .errors import Failure, fail
from .paths import HostPaths
from .sbx import Sbx

MODES = ("balanced", "web")

PROVIDER_HOSTS = {
    # The sandbox talks to the inference API only; authorization and refresh
    # endpoints (auth.openai.com, auth.kimi.com) are reached by the host.
    "openai": ["api.openai.com:443"],
    "kimi": ["api.kimi.com:443"],
}
GITHUB_HOSTS = [
    "github.com:443",
    "api.github.com:443",
    "codeload.github.com:443",
    "objects.githubusercontent.com:443",
    "raw.githubusercontent.com:443",
]
PACKAGE_HOSTS = ["registry.npmjs.org:443"]
WEB_HOSTS = ["**:443", "**:80"]

INTERNAL_DENY = [
    "localhost",
    "*.localhost",
    "host.docker.internal",
    "metadata.google.internal",
    "169.254.169.254",
    "127.0.0.0/8",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "169.254.0.0/16",
    "100.64.0.0/10",
    "0.0.0.0/8",
    "[::1]",
    "fc00::/7",
    "fe80::/10",
]


@dataclass(frozen=True)
class Plan:
    mode: str
    allow: tuple[str, ...]
    deny: tuple[str, ...]

    def describe(self) -> list[str]:
        lines = [f"network mode {self.mode} (sandbox-scoped):"]
        lines += [f"  allow {r}" for r in self.allow]
        lines += [f"  deny  {r}" for r in self.deny]
        if self.mode == "web":
            lines.append("  note: in web mode any agent or shell command in the sandbox can send study notes to any public site")
        return lines


def plan(mode: str, providers: list[str], *, github: bool = True) -> Plan:
    if mode not in MODES:
        raise fail(Failure.CONFIGURATION_INVALID, f"network mode must be one of {', '.join(MODES)}")
    allow: list[str] = []
    for provider in providers:
        allow += PROVIDER_HOSTS.get(provider, [])
    if github:
        allow += GITHUB_HOSTS
    allow += PACKAGE_HOSTS
    if mode == "web":
        allow += WEB_HOSTS
    seen: list[str] = []
    for item in allow:
        if item not in seen:
            seen.append(item)
    return Plan(mode, tuple(seen), tuple(INTERNAL_DENY))


def _state_file(paths: HostPaths, sandbox: str):
    return paths.state_dir / f"network-{sandbox}.json"


def apply(sbx: Sbx, paths: HostPaths, desired: Plan) -> list[str]:
    """Make the sandbox's Study Room rules equal ``desired``. Returns change lines."""
    state = fsutil.read_json(_state_file(paths, sbx.sandbox), {}) or {}
    had_allow = set(state.get("allow", []))
    had_deny = set(state.get("deny", []))
    changes: list[str] = []
    for resource in sorted(had_allow - set(desired.allow)):
        sbx.remove_rule(resource)
        changes.append(f"removed allow {resource}")
    for resource in sorted(had_deny - set(desired.deny)):
        sbx.remove_rule(resource)
        changes.append(f"removed deny {resource}")
    new_deny = [r for r in desired.deny if r not in had_deny]
    new_allow = [r for r in desired.allow if r not in had_allow]
    # Denies first: the narrowing rules are in place before egress widens.
    sbx.deny(new_deny)
    sbx.allow(new_allow)
    changes += [f"added deny {r}" for r in new_deny] + [f"added allow {r}" for r in new_allow]
    fsutil.atomic_write_json(_state_file(paths, sbx.sandbox), {"mode": desired.mode, "allow": list(desired.allow), "deny": list(desired.deny)})
    return changes


# A reserved name (RFC 2606) no baseline would allow: if the policy allows it,
# some rule allows arbitrary destinations. Checking evaluates rules only; no
# request or DNS lookup is made.
EGRESS_PROBE = "study-room-egress-probe.example:443"


def wider_than_balanced(sbx: Sbx) -> bool:
    return sbx.check(EGRESS_PROBE)


def forget(paths: HostPaths, sandbox: str) -> None:
    """The sandbox (and its scoped rules) is gone; drop the record."""
    try:
        _state_file(paths, sandbox).unlink()
    except FileNotFoundError:
        pass


def recorded_mode(paths: HostPaths, sandbox: str) -> str | None:
    state = fsutil.read_json(_state_file(paths, sandbox), {}) or {}
    return state.get("mode")
