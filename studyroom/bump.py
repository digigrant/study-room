"""`study-room bump <dependency>`: the explicit, reviewed way pins move (SPEC 17, 18).

1. discover the candidate version (latest, or --to);
2. show upstream changes and provenance;
3. update pins and checksums on a branch (never the default branch);
4. rebuild the sandbox image from scratch;
5. run the hermetic tests;
6. name the live checks that must be explicitly re-run;
7. leave a reviewable diff for a pull request.

Integrity values are computed from the downloaded artifacts, never typed in.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from . import lock as lockmod
from .errors import Failure, fail
from .http import Client
from .paths import repo_root
from .runner import Runner

DEPENDENCIES = (
    "@earendil-works/pi-coding-agent",
    "pi-web-search",
    "unpdf",
    "node",
    "obsidian",
    "docker-sbx",
    "sandbox-base",
    "learn",
    "pi-interactive-subagents",
    "verification-model",
)
LIVE_RELEVANT = {"@earendil-works/pi-coding-agent", "pi-web-search", "docker-sbx", "sandbox-base", "pi-interactive-subagents", "verification-model", "node"}


@dataclass
class BumpPlan:
    dependency: str
    old: str
    new: str
    provenance: list[str] = field(default_factory=list)
    apply: Callable[[dict], None] | None = None
    npm_changed: bool = False


def require_branch(runner: Runner, root: Path) -> str:
    branch = runner.run(["git", "-C", str(root), "rev-parse", "--abbrev-ref", "HEAD"], timeout=20).stdout.strip()
    default = runner.run(["git", "-C", str(root), "symbolic-ref", "--short", "refs/remotes/origin/HEAD"], timeout=20).stdout.strip().split("/")[-1] or "main"
    if branch in ("HEAD", "", default, "main", "master"):
        raise fail(Failure.CONFIGURATION_INVALID, f"pins move only on a topic branch (current: {branch or 'detached'})", hint="git checkout -b bump/<dependency>")
    dirty = runner.run(["git", "-C", str(root), "status", "--porcelain"], timeout=20).stdout.strip()
    if dirty:
        raise fail(Failure.CONFIGURATION_INVALID, "the checkout has uncommitted changes; commit or stash them before a bump")
    return branch


def _sha256_url(url: str) -> str:
    h = hashlib.sha256()
    with urllib.request.urlopen(url, timeout=300) as resp:  # noqa: S310 - pinned upstream hosts
        for chunk in iter(lambda: resp.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def plan_npm(lock: lockmod.Lock, client: Client, name: str, to: str | None) -> BumpPlan:
    pin = lock["npm"]["packages"][name]
    meta = client.request("GET", f"https://registry.npmjs.org/{name.replace('/', '%2f')}", timeout=30).json()
    version = to or meta["dist-tags"]["latest"]
    if version not in meta.get("versions", {}):
        raise fail(Failure.PIN_MISMATCH, f"{name}@{version} does not exist on npm")
    info = meta["versions"][version]
    repo = (info.get("repository") or {}).get("url", "")
    prov = [
        f"npm: https://www.npmjs.com/package/{name}/v/{version}",
        f"tarball: {info['dist']['tarball']}",
        f"integrity: {info['dist']['integrity']}",
        f"license: {info.get('license')}",
        f"source: {repo} @ {info.get('gitHead', 'unknown')}",
    ]
    if info.get("dist", {}).get("attestations"):
        prov.append("npm provenance attestation: present")

    def apply(data: dict) -> None:
        data["npm"]["packages"][name].update(version=version, integrity=info["dist"]["integrity"], git_head=info.get("gitHead"), license=info.get("license"))

    return BumpPlan(name, pin["version"], version, prov, apply, npm_changed=True)


def plan_node(lock: lockmod.Lock, client: Client, to: str | None) -> BumpPlan:
    index = client.request("GET", "https://nodejs.org/dist/index.json", timeout=30).json()
    candidates = [r for r in index if str(r["version"]).startswith("v22.")]
    chosen = next((r for r in candidates if r["version"] == f"v{to}"), None) if to else max(candidates, key=lambda r: tuple(int(x) for x in r["version"][1:].split(".")))
    if not chosen:
        raise fail(Failure.PIN_MISMATCH, f"Node {to} is not a 22.x release")
    version = chosen["version"][1:]
    shasums = client.request("GET", f"https://nodejs.org/dist/v{version}/SHASUMS256.txt", timeout=30).text()
    artifact = f"node-v{version}-linux-x64.tar.xz"
    m = re.search(rf"^([0-9a-f]{{64}})\s+{re.escape(artifact)}$", shasums, re.MULTILINE)
    if not m:
        raise fail(Failure.PIN_MISMATCH, f"no checksum for {artifact}")
    sha = m.group(1)
    prov = [f"release: https://nodejs.org/en/blog/release/v{version}", f"npm {chosen['npm']}, security release: {chosen.get('security')}", f"{artifact} sha256 {sha} (SHASUMS256.txt)"]

    def apply(data: dict) -> None:
        data["node"].update(version=version, npm_version=chosen["npm"], artifact=artifact, url=f"https://nodejs.org/dist/v{version}/{artifact}", sha256=sha)

    return BumpPlan("node", lock["node"]["version"], version, prov, apply, npm_changed=True)


def plan_obsidian(lock: lockmod.Lock, client: Client, to: str | None) -> BumpPlan:
    path = f"tags/v{to}" if to else "latest"
    rel = client.request("GET", f"https://api.github.com/repos/obsidianmd/obsidian-releases/releases/{path}", timeout=30).json()
    version = str(rel["tag_name"]).lstrip("v")
    asset = next(a for a in rel["assets"] if a["name"] == f"obsidian_{version}_amd64.deb")
    sha = _sha256_url(asset["browser_download_url"])
    if asset.get("digest") and asset["digest"] != f"sha256:{sha}":
        raise fail(Failure.PIN_MISMATCH, "the downloaded Obsidian .deb does not match GitHub's published digest")
    prov = [f"release: {rel['html_url']}", f"asset: {asset['browser_download_url']}", f"sha256 {sha} (computed; GitHub digest {asset.get('digest', 'n/a')})"]

    def apply(data: dict) -> None:
        data["obsidian_desktop"].update(version=version, url=asset["browser_download_url"], sha256=sha, size=asset["size"])

    return BumpPlan("obsidian", lock["obsidian_desktop"]["version"], version, prov, apply)


def plan_sbx(lock: lockmod.Lock, client: Client, to: str | None) -> BumpPlan:
    rel = client.request("GET", "https://api.github.com/repos/docker/sbx-releases/releases/" + (f"tags/v{to}" if to else "latest"), timeout=30).json()
    version = str(rel["tag_name"]).lstrip("v")
    prov = [f"release: {rel['html_url']}", "notes: https://docs.docker.com/ai/sandboxes/release-notes/"]

    def apply(data: dict) -> None:
        data["docker_sandboxes"]["version"] = version
        for p in data["system_packages"]["host"]:
            if p["name"] == "docker-sbx":
                p["constraint"] = f"= {version}"

    return BumpPlan("docker-sbx", lock["docker_sandboxes"]["version"], version, prov, apply)


def plan_base(lock: lockmod.Lock, runner: Runner, to: str | None) -> BumpPlan:
    base = lock["sandbox_image"]["base"]
    repo = base["reference"].split(":")[0]
    tag = to or base["reference"].split(":")[1]
    ref = f"{repo}:{tag}"
    res = runner.run(["docker", "buildx", "imagetools", "inspect", ref, "--format", "{{json .}}"], timeout=120)
    if not res.ok:
        raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, f"cannot inspect {ref}: {res.stderr.strip()[:200]}")
    data_out = json.loads(res.stdout)
    digest = data_out["manifest"]["digest"]
    amd = next((m["digest"] for m in data_out["manifest"].get("manifests", []) if m.get("platform", {}).get("architecture") == "amd64"), digest)
    prov = [f"image: {ref}", f"index digest {digest}", f"linux/amd64 manifest {amd}"]

    def apply(data: dict) -> None:
        data["sandbox_image"]["base"].update(reference=ref, digest=digest, platform_manifest_digest=amd)

    return BumpPlan("sandbox-base", f"{base['reference']}@{base['digest'][:19]}", f"{ref}@{digest[:19]}", prov, apply)


def plan_git(lock: lockmod.Lock, runner: Runner, name: str, to: str | None) -> BumpPlan:
    src = lock.git_source(name)
    commit = to
    if not commit:
        res = runner.run(["git", "ls-remote", src["url"], "HEAD"], timeout=60)
        commit = res.stdout.split()[0] if res.ok and res.stdout.strip() else None
    if not commit or not re.fullmatch(r"[0-9a-f]{40}", commit):
        raise fail(Failure.PIN_MISMATCH, f"could not resolve a full commit for {name}")
    tmp = Path(tempfile.mkdtemp(prefix="sr-bump-"))
    try:
        runner.run(["git", "init", "-q", str(tmp)], timeout=30)
        fetched = runner.run(["git", "-C", str(tmp), "fetch", "-q", "--depth", "1", src["url"], commit], timeout=300)
        if not fetched.ok:
            raise fail(Failure.PIN_MISMATCH, f"cannot fetch {name} {commit}")
        tree = runner.run(["git", "-C", str(tmp), "rev-parse", "FETCH_HEAD^{tree}"], timeout=30).stdout.strip()
        files = runner.run(["git", "-C", str(tmp), "ls-tree", "-r", "--name-only", "FETCH_HEAD"], timeout=30).stdout.split()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if name == "learn":
        missing = [r for r in lockmod.APPROVED_LEARN_RESOURCES if not any(f == r or f.startswith(r + "/") for f in files)]
        if missing:
            raise fail(Failure.PIN_MISMATCH, f"the new Learn commit lacks approved resources: {', '.join(missing)}")
        if any(f.lower().startswith("license") for f in files):
            prov_license = "Learn now ships a license file: review it and update git_sources.learn.license"
        else:
            prov_license = "Learn still declares no license (V1 does not vendor or publish it)"
    else:
        prov_license = f"license on record: {src.get('license')}"
    gh = src["url"].removesuffix(".git")
    prov = [f"compare: {gh}/compare/{src['commit']}...{commit}", f"tree {tree}", prov_license]

    def apply(data: dict) -> None:
        data["git_sources"][name].update(commit=commit, tree=tree)

    return BumpPlan(name, src["commit"][:12], commit[:12], prov, apply)


def plan_verification_model(lock: lockmod.Lock, provider: str, model: str) -> BumpPlan:
    prof = lock.verification_model(provider)

    def apply(data: dict) -> None:
        data["verification"][provider].update(model=model, status="pinned", note=f"Pinned after inspecting the authenticated {provider} catalog.")

    return BumpPlan(f"verification-model {provider}", f"{prof['model']} ({prof['status']})", f"{model} (pinned)", ["source: `study-room models " + provider + "` output reviewed by the user"], apply)


def write_lock(root: Path, data: dict) -> None:
    (root / lockmod.LOCK_RELATIVE).write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def regenerate_npm(root: Path, data: dict, runner: Runner, client: Client) -> None:
    """Regenerate the runtime lockfile and installed-tree digest with the pinned Node/npm, in a container."""
    runtime = root / "sandbox" / "runtime"
    pkg = json.loads((runtime / "package.json").read_text())
    for name, pin in data["npm"]["packages"].items():
        pkg["dependencies"][name] = pin["version"]
    pkg["engines"]["node"] = data["node"]["version"]
    (runtime / "package.json").write_text(json.dumps(pkg, indent=2) + "\n")
    node_image = f"node:{data['node']['version']}-bookworm-slim"
    script = "npm install --package-lock-only --no-update-notifier"
    res = runner.run(["docker", "run", "--rm", "-v", f"{runtime}:/w", "-w", "/w", "--user", f"{_uid()}", node_image, "sh", "-c", script], timeout=900)
    if not res.ok:
        raise fail(Failure.PIN_MISMATCH, f"lockfile regeneration failed: {res.stderr.strip()[:300]}")
    lockfile = runtime / "package-lock.json"
    entries = json.loads(lockfile.read_text())
    for key, entry in entries["packages"].items():
        if key and not entry.get("integrity") and not entry.get("link"):
            name = key.split("node_modules/")[-1]
            meta = client.request("GET", f"https://registry.npmjs.org/{name.replace('/', '%2f')}/{entry['version']}", timeout=30).json()
            if meta["dist"]["tarball"] != entry.get("resolved"):
                raise fail(Failure.PIN_MISMATCH, f"{key} resolves to an unexpected tarball")
            entry["integrity"] = meta["dist"]["integrity"]
    lockfile.write_text(json.dumps(entries, indent=2) + "\n")
    data["npm"]["lockfile_sha256"] = lockmod.sha256_file(lockfile)
    digest = runner.run(
        ["docker", "run", "--rm", "-v", f"{runtime}:/src:ro", "-v", f"{root / 'sandbox' / 'bin'}:/bin-sr:ro", node_image, "sh", "-c",
         "cp -r /src /w && cd /w && npm ci --no-update-notifier >/dev/null 2>&1 && node /bin-sr/tree-digest.mjs node_modules"],
        timeout=1800,
    )
    if not digest.ok:
        raise fail(Failure.PIN_MISMATCH, f"npm ci for the tree digest failed: {digest.stderr.strip()[:300]}")
    sha, count = digest.stdout.split()
    data["npm"]["installed_tree_sha256"] = sha
    data["npm"]["installed_tree_entries"] = int(count)


def _uid() -> int:
    import os

    return os.getuid()


def run(
    dependency: str,
    args: list[str],
    *,
    runner: Runner,
    client: Client,
    to: str | None,
    confirm: Callable[[list[str]], bool],
    run_tests: Callable[[], int],
    rebuild: Callable[[lockmod.Lock], None],
    say=print,
) -> int:
    root = repo_root()
    branch = require_branch(runner, root)
    lock = lockmod.load(root)
    if dependency == "verification-model":
        if len(args) != 2:
            raise fail(Failure.CONFIGURATION_INVALID, "usage: study-room bump verification-model <provider> <model-id>")
        plan = plan_verification_model(lock, args[0], args[1])
    elif dependency in lock["npm"]["packages"]:
        plan = plan_npm(lock, client, dependency, to)
    elif dependency == "node":
        plan = plan_node(lock, client, to)
    elif dependency == "obsidian":
        plan = plan_obsidian(lock, client, to)
    elif dependency == "docker-sbx":
        plan = plan_sbx(lock, client, to)
    elif dependency == "sandbox-base":
        plan = plan_base(lock, runner, to)
    elif dependency in ("learn", "pi-interactive-subagents"):
        plan = plan_git(lock, runner, dependency, to)
    else:
        raise fail(Failure.CONFIGURATION_INVALID, f"unknown dependency {dependency!r}; choose from {', '.join(DEPENDENCIES)}")
    lines = [f"Bump {plan.dependency}: {plan.old} → {plan.new} on branch {branch}", *[f"  {p}" for p in plan.provenance]]
    if plan.old == plan.new:
        say("\n".join(lines + ["Already pinned; nothing to do."]))
        return 0
    if not confirm(lines):
        raise fail(Failure.PERMISSION_DECLINED, "bump cancelled; nothing changed")
    data = json.loads(json.dumps(lock.data))
    plan.apply(data)  # type: ignore[misc]
    if plan.npm_changed:
        say("Regenerating the npm lockfile and installed-tree digest with the pinned Node/npm...")
        regenerate_npm(root, data, runner, client)
    write_lock(root, data)
    new_lock = lockmod.load(root)
    lockmod.require_valid(new_lock)
    say("Rebuilding the sandbox image from scratch...")
    rebuild(new_lock)
    say("Running the hermetic tests...")
    if run_tests() != 0:
        raise fail(Failure.PIN_MISMATCH, "hermetic tests failed with the new pin; the change is left uncommitted for review")
    if dependency in LIVE_RELEVANT:
        say("This pin affects live plumbing: run `study-room verify --live` (explicit, consented) before merging.")
    diff = subprocess.run(["git", "-C", str(root), "diff", "--stat"], capture_output=True, text=True).stdout
    say(f"Review the change and open a pull request (nothing is merged automatically):\n{diff}")
    return 0
