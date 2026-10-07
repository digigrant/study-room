"""The checked-in lock manifest (SPEC 17).

``lock/study-room.lock.json`` is the authoritative record of every pin and
integrity value. This module loads it and validates both its own shape and
its consistency with the files it describes (the sandbox npm lockfile, the
Dockerfile build arguments, the approved Learn resource selection). A failed
validation is a ``PIN_MISMATCH`` failure: builds stop rather than continue
with an unverified or moved pin.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path

from .errors import Failure, fail
from .paths import repo_root

LOCK_RELATIVE = Path("lock/study-room.lock.json")

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")
SHA1_RE = re.compile(r"^[0-9a-f]{40}$")
SRI_RE = re.compile(r"^sha512-[A-Za-z0-9+/]{86}==$")
DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")

# SPEC 10.2: exactly these Learn resources load; these never do.
APPROVED_LEARN_RESOURCES = (
    "skills/teach",
    "extensions/ask-user-question.ts",
    "extensions/quiz.ts",
    "extensions/md-log.ts",
)
EXCLUDED_LEARN_RESOURCES = (
    "skills/visualize",
    "extensions/visual-tools",
    "agents/researcher.md",
    "agents/svg-maker.md",
    "agents/mermaid-maker.md",
)

ALLOWED_VERIFICATION_THINKING = ("off", "minimal", "low")
# Hard ceilings for live connectivity checks (SPEC 20.2). A lock entry above
# these is rejected, so a bump cannot quietly make live checks expensive.
MAX_VERIFICATION_REQUESTS = 4
MAX_VERIFICATION_OUTPUT_TOKENS = 512
MAX_VERIFICATION_TIMEOUT_SECONDS = 180


@dataclass(frozen=True)
class Lock:
    data: dict
    path: Path

    def __getitem__(self, key: str):
        return self.data[key]

    def get(self, key: str, default=None):
        return self.data.get(key, default)

    @property
    def fingerprint(self) -> str:
        """Stable hash of the pin set, recorded in verification receipts."""
        canonical = json.dumps(self.data, sort_keys=True, separators=(",", ":")).encode()
        return hashlib.sha256(canonical).hexdigest()

    def git_source(self, name: str) -> dict:
        return self.data["git_sources"][name]

    def verification_model(self, provider: str) -> dict:
        try:
            return self.data["verification"][provider]
        except KeyError:
            raise fail(
                Failure.CONFIGURATION_INVALID,
                f"the lock has no verification profile for provider {provider!r}",
            ) from None


def load(root: Path | None = None) -> Lock:
    root = root or repo_root()
    path = root / LOCK_RELATIVE
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise fail(Failure.PIN_MISMATCH, f"lock manifest missing: {path}") from None
    except ValueError as exc:
        raise fail(Failure.PIN_MISMATCH, f"lock manifest is not valid JSON: {exc}") from None
    return Lock(data, path)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


class _Collector:
    def __init__(self) -> None:
        self.problems: list[str] = []

    def check(self, condition: bool, message: str) -> None:
        if not condition:
            self.problems.append(message)

    def match(self, regex: re.Pattern[str], value: object, where: str) -> None:
        self.check(isinstance(value, str) and bool(regex.match(value)), f"{where}: malformed value {value!r}")


def validate(lock: Lock, root: Path | None = None) -> list[str]:
    """Return every problem found; an empty list means the lock is consistent."""
    root = root or lock.path.parent.parent
    c = _Collector()
    d = lock.data

    c.check(d.get("schema") == 1, "schema must be 1")

    sbx = d.get("docker_sandboxes", {})
    c.match(SEMVER_RE, sbx.get("version"), "docker_sandboxes.version")

    image = d.get("sandbox_image", {})
    base = image.get("base", {})
    c.check(isinstance(base.get("reference"), str) and "@" not in base.get("reference", "@"),
            "sandbox_image.base.reference must be a tag without a digest")
    c.match(DIGEST_RE, base.get("digest"), "sandbox_image.base.digest")
    c.check(image.get("publish") is False, "sandbox_image.publish must be false (SPEC 4: no image publication)")

    node = d.get("node", {})
    c.match(SEMVER_RE, node.get("version"), "node.version")
    c.match(SEMVER_RE, node.get("npm_version"), "node.npm_version")
    c.match(SHA256_RE, node.get("sha256"), "node.sha256")
    artifact = node.get("artifact", "")
    c.check(artifact == f"node-v{node.get('version')}-linux-x64.tar.xz", "node.artifact must name the linux-x64 tar.xz for node.version")
    c.check(str(node.get("url", "")).startswith(f"https://nodejs.org/dist/v{node.get('version')}/"),
            "node.url must point at nodejs.org/dist for node.version")

    npm = d.get("npm", {})
    lockfile_rel = npm.get("lockfile")
    c.match(SHA256_RE, npm.get("lockfile_sha256"), "npm.lockfile_sha256")
    c.match(SHA256_RE, npm.get("installed_tree_sha256"), "npm.installed_tree_sha256")
    c.check(isinstance(npm.get("installed_tree_entries"), int), "npm.installed_tree_entries must be an integer")
    packages = npm.get("packages", {})
    c.check(set(packages) == {"@earendil-works/pi-coding-agent", "pi-web-search", "unpdf"},
            "npm.packages must pin exactly pi-coding-agent, pi-web-search and unpdf")
    for name, pin in packages.items():
        c.match(SEMVER_RE, pin.get("version"), f"npm.packages[{name}].version")
        c.match(SRI_RE, pin.get("integrity"), f"npm.packages[{name}].integrity")
    if lockfile_rel:
        lockfile = root / lockfile_rel
        if not lockfile.exists():
            c.problems.append(f"npm lockfile missing: {lockfile_rel}")
        else:
            actual = sha256_file(lockfile)
            c.check(actual == npm.get("lockfile_sha256"),
                    f"npm lockfile {lockfile_rel} sha256 {actual} does not match the lock manifest")
            _validate_npm_lockfile(c, lockfile, packages)

    sources = d.get("git_sources", {})
    c.check(set(sources) == {"learn", "pi-interactive-subagents"}, "git_sources must be exactly learn and pi-interactive-subagents")
    for name, src in sources.items():
        c.check(str(src.get("url", "")).startswith("https://github.com/") and str(src.get("url", "")).endswith(".git"),
                f"git_sources[{name}].url must be an https github .git URL")
        c.match(SHA1_RE, src.get("commit"), f"git_sources[{name}].commit")
        c.match(SHA1_RE, src.get("tree"), f"git_sources[{name}].tree")
        c.check(str(src.get("checkout", "")).startswith("/opt/study-room/upstream/"),
                f"git_sources[{name}].checkout must live under /opt/study-room/upstream/ (SPEC 9.4)")
    learn = sources.get("learn", {})
    c.check(tuple(learn.get("load", ())) == APPROVED_LEARN_RESOURCES,
            "git_sources.learn.load must be exactly the approved resources (SPEC 10.2)")
    c.check(tuple(learn.get("never_load", ())) == EXCLUDED_LEARN_RESOURCES,
            "git_sources.learn.never_load must list the excluded resources (SPEC 10.2)")
    c.check(learn.get("modified") is False, "git_sources.learn.modified must be false: Learn is consumed unmodified")
    c.check(sources.get("pi-interactive-subagents", {}).get("license") == "MIT",
            "pi-interactive-subagents license must be recorded as MIT")

    obs = d.get("obsidian_desktop", {})
    c.match(SEMVER_RE, obs.get("version"), "obsidian_desktop.version")
    c.match(SHA256_RE, obs.get("sha256"), "obsidian_desktop.sha256")
    c.check(obs.get("architecture") == "amd64", "obsidian_desktop.architecture must be amd64 (x86_64 only, SPEC 4)")
    c.check(str(obs.get("url", "")).startswith("https://github.com/obsidianmd/obsidian-releases/releases/download/"),
            "obsidian_desktop.url must be an obsidianmd/obsidian-releases download")
    c.check(str(obs.get("url", "")).endswith(f"obsidian_{obs.get('version')}_amd64.deb"),
            "obsidian_desktop.url must name the pinned version's amd64 .deb")

    for scope in ("host", "sandbox"):
        pkgs = d.get("system_packages", {}).get(scope)
        c.check(isinstance(pkgs, list) and all(isinstance(p, dict) and p.get("name") for p in pkgs or []),
                f"system_packages.{scope} must be a list of {{name, constraint}}")

    verification = d.get("verification", {})
    c.check("openai" in verification, "verification.openai must exist (OpenAI is the initial release path)")
    for provider, prof in verification.items():
        where = f"verification.{provider}"
        c.check(prof.get("status") in ("pinned", "candidate"), f"{where}.status must be pinned or candidate")
        c.check(isinstance(prof.get("model"), str) and bool(prof.get("model")), f"{where}.model must be set")
        c.check(prof.get("thinking") in ALLOWED_VERIFICATION_THINKING, f"{where}.thinking must be off, minimal or low")
        limits = prof.get("limits", {})
        c.check(isinstance(limits.get("max_requests"), int) and 1 <= limits["max_requests"] <= MAX_VERIFICATION_REQUESTS,
                f"{where}.limits.max_requests must be 1..{MAX_VERIFICATION_REQUESTS}")
        c.check(isinstance(limits.get("max_output_tokens"), int) and 1 <= limits["max_output_tokens"] <= MAX_VERIFICATION_OUTPUT_TOKENS,
                f"{where}.limits.max_output_tokens must be 1..{MAX_VERIFICATION_OUTPUT_TOKENS}")
        c.check(isinstance(limits.get("timeout_seconds"), int) and 1 <= limits["timeout_seconds"] <= MAX_VERIFICATION_TIMEOUT_SECONDS,
                f"{where}.limits.timeout_seconds must be 1..{MAX_VERIFICATION_TIMEOUT_SECONDS}")
        research = prof.get("research_limits", {})
        c.check(isinstance(research.get("max_model_turns"), int) and 1 <= research["max_model_turns"] <= MAX_VERIFICATION_REQUESTS,
                f"{where}.research_limits.max_model_turns must be 1..{MAX_VERIFICATION_REQUESTS}")
        c.check(research.get("max_search_calls") == 1, f"{where}.research_limits.max_search_calls must be 1")

    c.check(d.get("patches") == [], "patches must be empty: V1 applies no project-owned patches")
    _validate_dockerfile(c, root, d)
    return c.problems


def _validate_npm_lockfile(c: _Collector, lockfile: Path, pins: dict) -> None:
    try:
        data = json.loads(lockfile.read_text(encoding="utf-8"))
    except ValueError:
        c.problems.append("npm lockfile is not valid JSON")
        return
    c.check(data.get("lockfileVersion") == 3, "npm lockfile must be lockfileVersion 3")
    entries = data.get("packages", {})
    for key, entry in entries.items():
        if not key or entry.get("link"):
            continue
        c.check(SRI_RE.match(str(entry.get("integrity", ""))) is not None, f"npm lockfile entry {key} has no sha512 integrity")
        c.check(str(entry.get("resolved", "")).startswith("https://registry.npmjs.org/"),
                f"npm lockfile entry {key} must resolve from registry.npmjs.org")
    for name, pin in pins.items():
        entry = entries.get(f"node_modules/{name}", {})
        c.check(entry.get("version") == pin.get("version"), f"npm lockfile pins {name}@{entry.get('version')}, lock says {pin.get('version')}")
        c.check(entry.get("integrity") == pin.get("integrity"), f"npm lockfile integrity for {name} differs from the lock manifest")
    root_deps = entries.get("", {}).get("dependencies", {})
    for name, pin in pins.items():
        c.check(root_deps.get(name) == pin.get("version"), f"sandbox/runtime/package.json must depend on exactly {name}@{pin.get('version')}")


def _validate_dockerfile(c: _Collector, root: Path, d: dict) -> None:
    dockerfile = root / "sandbox" / "Dockerfile"
    if not dockerfile.exists():
        c.problems.append("sandbox/Dockerfile missing")
        return
    text = dockerfile.read_text(encoding="utf-8")
    # Every pinned value reaches the build as a required build argument; the
    # Dockerfile itself carries no defaults that could drift from the lock.
    for arg in build_args(d):
        c.check(re.search(rf"^ARG {arg}$", text, re.MULTILINE) is not None, f"sandbox/Dockerfile must declare ARG {arg} without a default")
    c.check(re.search(r"^ARG \w+=", text, re.MULTILINE) is None, "sandbox/Dockerfile ARGs must not carry defaults")
    froms = re.findall(r"^FROM\s+(\S+)", text, re.MULTILINE)
    c.check(bool(froms) and all(ref == "${BASE_IMAGE}" for ref in froms),
            "sandbox/Dockerfile must build only FROM ${BASE_IMAGE} (the digest-pinned base)")


def build_args(d: dict) -> dict[str, str]:
    """Docker build arguments derived from the lock; the only source of pins for the image."""
    node = d["node"]
    learn = d["git_sources"]["learn"]
    subagents = d["git_sources"]["pi-interactive-subagents"]
    base = d["sandbox_image"]["base"]
    return {
        "BASE_IMAGE": f"{base['reference']}@{base['digest']}",
        "NODE_VERSION": node["version"],
        "NODE_SHA256": node["sha256"],
        "NPM_TREE_SHA256": d["npm"]["installed_tree_sha256"],
        "LEARN_URL": learn["url"],
        "LEARN_COMMIT": learn["commit"],
        "LEARN_TREE": learn["tree"],
        "SUBAGENTS_URL": subagents["url"],
        "SUBAGENTS_COMMIT": subagents["commit"],
        "SUBAGENTS_TREE": subagents["tree"],
        "SANDBOX_APT_PACKAGES": " ".join(p["name"] for p in d["system_packages"]["sandbox"]),
        "SANDBOX_APT_CONSTRAINTS": " ".join(_apt_constraint(p) for p in d["system_packages"]["sandbox"]),
    }


def _apt_constraint(pkg: dict) -> str:
    op, _, version = str(pkg["constraint"]).partition(" ")
    return f"{pkg['name']}:{op}:{version}"


def require_valid(lock: Lock, root: Path | None = None) -> None:
    problems = validate(lock, root)
    if problems:
        raise fail(
            Failure.PIN_MISMATCH,
            "lock manifest validation failed:\n  - " + "\n  - ".join(problems),
            hint="run `study-room bump <dependency>` to change pins; never edit integrity values by hand",
        )
