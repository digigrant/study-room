"""Entry-time dependency drift notices (SPEC 18).

Normal entry reads a cached result immediately and refreshes it at most once
per configurable interval (default 24 hours). A refresh uses short timeouts;
an unreachable update source never blocks entry. Nothing is installed: the
result only feeds the entry banner and `study-room check-updates`.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import asdict, dataclass
from typing import Callable

from . import fsutil
from .errors import StudyRoomError
from .http import Client
from .lock import Lock
from .paths import HostPaths
from .runner import Runner

TIMEOUT = 8


@dataclass
class Drift:
    dependency: str
    pinned: str
    latest: str | None
    stale: bool
    error: str | None = None


def _semver_key(v: str) -> tuple:
    return tuple(int(x) for x in re.findall(r"\d+", v)[:3])


def _npm_latest(client: Client, name: str) -> str:
    resp = client.request("GET", f"https://registry.npmjs.org/{name.replace('/', '%2f')}/latest", timeout=TIMEOUT)
    data = resp.json()
    if not resp.ok or not isinstance(data, dict) or "version" not in data:
        raise RuntimeError(f"registry answered {resp.status}")
    return str(data["version"])


def _github_latest_release(client: Client, repo: str) -> str:
    resp = client.request("GET", f"https://api.github.com/repos/{repo}/releases/latest", timeout=TIMEOUT)
    data = resp.json()
    if not resp.ok or not isinstance(data, dict) or "tag_name" not in data:
        raise RuntimeError(f"GitHub answered {resp.status}")
    return str(data["tag_name"]).lstrip("v")


def _node_latest_22(client: Client) -> str:
    resp = client.request("GET", "https://nodejs.org/dist/index.json", timeout=TIMEOUT)
    data = resp.json()
    if not resp.ok or not isinstance(data, list):
        raise RuntimeError(f"nodejs.org answered {resp.status}")
    versions = [str(r["version"]).lstrip("v") for r in data if isinstance(r, dict) and str(r.get("version", "")).startswith("v22.")]
    return max(versions, key=_semver_key)


def _git_head(runner: Runner, url: str) -> str:
    res = runner.run(["git", "ls-remote", url, "HEAD"], timeout=TIMEOUT)
    if not res.ok or not res.stdout.strip():
        raise RuntimeError("git ls-remote failed")
    return res.stdout.split()[0]


def _sandbox_template_latest(client: Client) -> str:
    resp = client.request(
        "GET", "https://hub.docker.com/v2/repositories/docker/sandbox-templates/tags/?page_size=100&name=shell-", timeout=TIMEOUT
    )
    data = resp.json()
    names = [str(t.get("name")) for t in (data.get("results", []) if isinstance(data, dict) else []) if re.match(r"^shell-\d+\.\d+\.\d+$", str(t.get("name")))]
    if not names:
        raise RuntimeError(f"Docker Hub answered {resp.status}")
    return max(names, key=_semver_key)


def check(lock: Lock, client: Client, runner: Runner) -> list[Drift]:
    d = lock.data
    checks: list[tuple[str, str, Callable[[], str], bool]] = [
        ("docker-sbx", d["docker_sandboxes"]["version"], lambda: _github_latest_release(client, "docker/sbx-releases"), True),
        ("node", d["node"]["version"], lambda: _node_latest_22(client), True),
        ("obsidian", d["obsidian_desktop"]["version"], lambda: _github_latest_release(client, "obsidianmd/obsidian-releases"), True),
        ("sandbox-base", d["sandbox_image"]["base"]["reference"].split(":")[-1], lambda: _sandbox_template_latest(client), True),
    ]
    for name, pin in d["npm"]["packages"].items():
        checks.append((name, pin["version"], lambda n=name: _npm_latest(client, n), True))
    for name, src in d["git_sources"].items():
        checks.append((name, src["commit"][:12], lambda u=src["url"]: _git_head(runner, u)[:12], False))
    out: list[Drift] = []
    for name, pinned, fetch, semver in checks:
        try:
            latest = fetch()
            stale = (_semver_key(latest) > _semver_key(pinned)) if semver else latest != pinned
            out.append(Drift(name, pinned, latest, stale))
        except (StudyRoomError, RuntimeError, OSError, ValueError, KeyError) as exc:
            out.append(Drift(name, pinned, None, False, str(exc)[:120]))
    return out


def read_cache(paths: HostPaths, lock: Lock, interval_hours: float, *, now: float | None = None) -> tuple[list[Drift], bool]:
    """Cached results and whether they are still fresh; never touches the network."""
    now = time.time() if now is None else now
    data = fsutil.read_json(paths.update_cache_file, {}) or {}
    fresh = data.get("fingerprint") == lock.fingerprint and now - float(data.get("checked_at", 0)) < interval_hours * 3600
    return [Drift(**r) for r in data.get("results", [])], fresh


def cached(paths: HostPaths, lock: Lock, interval_hours: float, refresh: Callable[[], list[Drift]], *, now: float | None = None, force: bool = False) -> tuple[list[Drift], float | None]:
    """Return (results, checked_at). Refresh only when stale; keep the cache on failure."""
    now = time.time() if now is None else now
    data = fsutil.read_json(paths.update_cache_file, {}) or {}
    fresh = data.get("fingerprint") == lock.fingerprint and now - float(data.get("checked_at", 0)) < interval_hours * 3600
    if fresh and not force:
        return [Drift(**r) for r in data.get("results", [])], data.get("checked_at")
    try:
        results = refresh()
    except Exception:  # noqa: BLE001 - an update service never blocks entry
        return [Drift(**r) for r in data.get("results", [])], data.get("checked_at")
    fsutil.atomic_write_json(paths.update_cache_file, {"fingerprint": lock.fingerprint, "checked_at": now, "results": [asdict(r) for r in results]})
    return results, now


def banner_lines(results: list[Drift]) -> list[str]:
    stale = [r for r in results if r.stale]
    if not stale:
        return []
    items = ", ".join(f"{r.dependency} {r.pinned}→{r.latest}" for r in stale)
    return [f"newer upstream versions exist (not installed): {items}. Review with `study-room check-updates`; change pins with `study-room bump`."]


def render(results: list[Drift], checked_at: float | None) -> list[str]:
    when = time.strftime("%Y-%m-%d %H:%M", time.localtime(checked_at)) if checked_at else "never"
    lines = [f"Dependency drift (checked {when}; nothing is installed automatically):"]
    for r in results:
        if r.error:
            lines.append(f"  ?     {r.dependency}: pinned {r.pinned}; check failed ({r.error})")
        else:
            lines.append(f"  {'STALE' if r.stale else 'ok   '} {r.dependency}: pinned {r.pinned}, latest {r.latest}")
    return lines


def to_json(results: list[Drift]) -> str:
    return json.dumps([asdict(r) for r in results], indent=2)
