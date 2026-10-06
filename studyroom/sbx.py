"""Thin wrapper over the Docker Sandboxes CLI (`sbx`, pinned 0.46.0).

Only sandbox-scoped operations are used: secrets and network rules are
always set with ``--sandbox <name>``, so Study Room never changes global
Docker Sandboxes state except the one-time ``sbx policy init`` that setup
proposes, shows, and asks for (SPEC 13.2).

Command-backed secrets store their command text in plain text inside Docker
Sandboxes' state, so a command holds only absolute paths and a provider
name, never a secret.
"""

from __future__ import annotations

import json
import shlex
from dataclasses import dataclass

from .errors import Failure, fail
from .runner import Result, Runner


@dataclass
class CustomSecret:
    env: str
    placeholder: str
    targets: list[str]
    source: str | None


class Sbx:
    def __init__(self, runner: Runner, sandbox: str):
        self.runner = runner
        self.sandbox = sandbox

    def _run(self, *args: str, input: str | None = None, timeout: float = 120, check: bool = True) -> Result:
        res = self.runner.run(["sbx", *args], input=input, timeout=timeout)
        if res.returncode == 127:
            raise fail(Failure.MISSING_PREREQUISITE, "Docker Sandboxes (sbx) is not installed", hint="run `study-room setup`")
        if check and not res.ok:
            text = (res.stderr or res.stdout).strip().splitlines()
            line = text[0] if text else f"exit {res.returncode}"
            lowered = (res.stderr + res.stdout).lower()
            if "login" in lowered and ("not logged" in lowered or "sbx login" in lowered):
                raise fail(Failure.MISSING_PREREQUISITE, "Docker Sandboxes is not signed in", hint="run `sbx login` (interactive)")
            if "blocked by" in lowered or "denied" in lowered and "policy" in lowered:
                raise fail(Failure.NETWORK_POLICY_BLOCKED, f"sbx {args[0]}: {line}")
            raise fail(Failure.EXTERNAL_SERVICE_UNAVAILABLE, f"sbx {' '.join(args[:2])} failed: {line}")
        return res

    # --- state -----------------------------------------------------------
    def list_sandboxes(self) -> list[dict]:
        res = self._run("ls", "--json")
        try:
            data = json.loads(res.stdout or "{}")
        except ValueError:
            return []
        items = data.get("sandboxes", data) if isinstance(data, dict) else data
        return [s for s in items if isinstance(s, dict)]

    def exists(self) -> bool:
        return any(s.get("name") == self.sandbox for s in self.list_sandboxes())

    def status(self) -> str | None:
        for s in self.list_sandboxes():
            if s.get("name") == self.sandbox:
                return str(s.get("status", "unknown"))
        return None

    # --- templates --------------------------------------------------------
    def template_names(self) -> set[str]:
        res = self._run("template", "ls", "--json")
        try:
            data = json.loads(res.stdout or "[]")
        except ValueError:
            return set()
        items = data.get("templates", data) if isinstance(data, dict) else data
        names: set[str] = set()
        for t in items if isinstance(items, list) else []:
            if isinstance(t, dict):
                for key in ("name", "Name", "reference", "image"):
                    if isinstance(t.get(key), str):
                        names.add(t[key])
            elif isinstance(t, str):
                names.add(t)
        return names

    def has_template(self, tag: str) -> bool:
        """True when the template is loaded. Matches the raw listing too, so an
        unexpected JSON shape never forces a rebuild and reload."""
        if tag in self.template_names():
            return True
        res = self._run("template", "ls", check=False)
        listing = res.stdout
        repo, _, version = tag.partition(":")
        return tag in listing or f"docker.io/{tag}" in listing or any(repo in line and version in line for line in listing.splitlines())

    def template_load(self, tar_path: str) -> None:
        self._run("template", "load", tar_path, timeout=1800)

    def template_rm(self, name: str) -> None:
        self._run("template", "rm", "-f", name, check=False)

    # --- lifecycle --------------------------------------------------------
    def create(self, template: str, workspace: str) -> None:
        """Create the sandbox with only ``workspace`` (the vault's Study Room/) mounted read-write."""
        self._run(
            "create",
            "--name", self.sandbox,
            "--template", template,
            "--pull", "never",
            "--skills", "off",
            "shell",
            workspace,
            timeout=900,
        )

    def exec(self, argv: list[str], *, user: str | None = None, input: str | None = None, interactive: bool = False, env: dict[str, str] | None = None) -> Result:
        args = ["exec"]
        if interactive:
            args.append("-i")
        if user:
            args += ["-u", user]
        for key, value in (env or {}).items():
            args += ["-e", f"{key}={value}"]
        args.append(self.sandbox)
        args += argv
        return self._run(*args, input=input, timeout=600, check=False)

    def attach(self, argv: list[str]) -> int:
        """Interactive entry: `sbx exec -it <sandbox> ...` attached to this terminal."""
        return self.runner.interactive(["sbx", "exec", "-it", self.sandbox, *argv])

    def stop(self) -> None:
        self._run("stop", self.sandbox, check=False)

    def remove(self) -> None:
        """Remove the sandbox, its disposable state and its sandbox-scoped secrets; host files remain."""
        self._run("rm", "-f", self.sandbox, timeout=300)

    # --- secrets ----------------------------------------------------------
    def custom_secrets(self) -> list[CustomSecret]:
        res = self._run("secret", "ls", "--sandbox", self.sandbox, "--json")
        try:
            data = json.loads(res.stdout or "{}")
        except ValueError:
            return []
        out = []
        for item in data.get("custom_secrets", []) if isinstance(data, dict) else []:
            if item.get("scope") not in (self.sandbox, None):
                continue
            out.append(CustomSecret(str(item.get("env")), str(item.get("placeholder")), list(item.get("targets", [])), item.get("source")))
        return out

    def service_secrets(self) -> list[dict]:
        res = self._run("secret", "ls", "--sandbox", self.sandbox, "--json")
        try:
            data = json.loads(res.stdout or "{}")
        except ValueError:
            return []
        return [s for s in data.get("secrets", []) if isinstance(s, dict) and s.get("scope") in (self.sandbox, None)] if isinstance(data, dict) else []

    def set_custom(self, *, env: str, hosts: list[str], command: str, refresh: str, placeholder: str) -> None:
        args = ["secret", "set-custom", "--sandbox", self.sandbox, "--env", env]
        for host in hosts:
            args += ["--host", host]
        args += ["--placeholder", placeholder, "--command", command, "--refresh", refresh]
        self._run(*args, timeout=180)

    def set_service(self, service: str, *, command: str, refresh: str) -> None:
        self._run("secret", "set", service, "--sandbox", self.sandbox, "--command", command, "--refresh", refresh, timeout=180)

    def remove_custom(self, env: str, host: str) -> None:
        self._run("secret", "rm", "--sandbox", self.sandbox, "--host", host, "--env", env, "-f", check=False)

    # --- network policy ---------------------------------------------------
    def policy_rules(self) -> list[dict]:
        res = self._run("policy", "ls", self.sandbox, "--json", check=False)
        if not res.ok:
            return []
        try:
            data = json.loads(res.stdout or "[]")
        except ValueError:
            return []
        items = data.get("rules", data) if isinstance(data, dict) else data
        return [r for r in items if isinstance(r, dict)] if isinstance(items, list) else []

    def policy_initialized(self) -> bool:
        res = self._run("policy", "ls", "--json", check=False)
        text = (res.stdout + res.stderr).lower()
        return res.ok and "not initialized" not in text and "policy init" not in text

    def policy_init(self, preset: str) -> None:
        self._run("policy", "init", preset)

    def allow(self, resources: list[str]) -> None:
        if resources:
            self._run("policy", "allow", "network", "--sandbox", self.sandbox, ",".join(resources))

    def deny(self, resources: list[str]) -> None:
        if resources:
            self._run("policy", "deny", "network", "--sandbox", self.sandbox, ",".join(resources))

    def remove_rule(self, resource: str) -> None:
        self._run("policy", "rm", "network", "--sandbox", self.sandbox, "--resource", resource, "-f", check=False)

    def check(self, target: str) -> bool:
        res = self._run("policy", "check", "network", "--sandbox", self.sandbox, target, check=False)
        return res.ok and res.stdout.strip().lower().startswith("allowed")


def resolver_command(study_room_bin: str, name: str) -> str:
    """Command text Docker Sandboxes stores and runs on the host: a path and a name only."""
    return f"{shlex.quote(study_room_bin)} resolve {shlex.quote(name)}"
