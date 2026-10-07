"""Subprocess execution behind a seam the hermetic tests replace.

Secrets are never passed as process arguments (SPEC 15.1): callers hand them
to ``run(..., input=...)`` on stdin instead. ``Runner.run`` records argv for
tests and redacts it before it reaches any log.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Mapping, Sequence

from . import redact


@dataclass
class Result:
    argv: list[str]
    returncode: int
    stdout: str = ""
    stderr: str = ""

    @property
    def ok(self) -> bool:
        return self.returncode == 0


class Runner:
    """Runs real commands. Subclassed by ``FakeRunner`` in tests."""

    def which(self, name: str) -> str | None:
        return shutil.which(name)

    def run(
        self,
        argv: Sequence[str],
        *,
        input: str | None = None,
        env: Mapping[str, str] | None = None,
        timeout: float | None = 120,
        cwd: str | None = None,
        check: bool = False,
    ) -> Result:
        merged_env = None
        if env is not None:
            merged_env = dict(os.environ)
            merged_env.update(env)
        try:
            proc = subprocess.run(
                list(argv),
                input=input,
                capture_output=True,
                text=True,
                env=merged_env,
                timeout=timeout,
                cwd=cwd,
            )
        except FileNotFoundError:
            return Result(list(argv), 127, "", f"{argv[0]}: command not found")
        except subprocess.TimeoutExpired:
            return Result(list(argv), 124, "", f"{argv[0]}: timed out after {timeout}s")
        result = Result(list(argv), proc.returncode, proc.stdout, proc.stderr)
        if check and not result.ok:
            raise subprocess.CalledProcessError(
                result.returncode, redact.redact_text(" ".join(argv)), result.stdout, redact.redact_text(result.stderr)
            )
        return result

    def interactive(self, argv: Sequence[str], *, env: Mapping[str, str] | None = None) -> int:
        """Run attached to the terminal (sudo prompts, tmux attach, GUI launch)."""
        merged_env = None
        if env is not None:
            merged_env = dict(os.environ)
            merged_env.update(env)
        try:
            return subprocess.call(list(argv), env=merged_env)
        except FileNotFoundError:
            return 127

    def spawn_detached(self, argv: Sequence[str], *, env: Mapping[str, str] | None = None) -> int:
        """Start a long-lived GUI process (Obsidian) without tying it to this terminal."""
        merged_env = dict(os.environ)
        if env is not None:
            merged_env.update(env)
        proc = subprocess.Popen(
            list(argv),
            env=merged_env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return proc.pid


Handler = Callable[[list[str], "str | None"], Result]


@dataclass
class FakeRunner(Runner):
    """Scriptable runner for tests: maps argv prefixes to canned results."""

    handlers: list[tuple[tuple[str, ...], Handler]] = field(default_factory=list)
    calls: list[tuple[list[str], str | None]] = field(default_factory=list)
    available: set[str] = field(default_factory=set)
    interactive_calls: list[list[str]] = field(default_factory=list)
    detached_calls: list[list[str]] = field(default_factory=list)

    def which(self, name: str) -> str | None:
        return f"/usr/bin/{name}" if name in self.available else None

    def on(self, prefix: Sequence[str], handler: Handler | Result | str | int) -> "FakeRunner":
        if isinstance(handler, Result):
            fixed = handler
            fn: Handler = lambda argv, _input: Result(argv, fixed.returncode, fixed.stdout, fixed.stderr)
        elif isinstance(handler, str):
            text = handler
            fn = lambda argv, _input: Result(argv, 0, text, "")
        elif isinstance(handler, int):
            code = handler
            fn = lambda argv, _input: Result(argv, code, "", "")
        else:
            fn = handler
        self.handlers.insert(0, (tuple(prefix), fn))
        return self

    def run(self, argv, *, input=None, env=None, timeout=None, cwd=None, check=False) -> Result:
        argv = list(argv)
        self.calls.append((argv, input))
        for prefix, fn in self.handlers:
            if tuple(argv[: len(prefix)]) == prefix:
                return fn(argv, input)
        return Result(argv, 127, "", f"{argv[0]}: no fake handler")

    def interactive(self, argv, *, env=None) -> int:
        argv = list(argv)
        self.interactive_calls.append(argv)
        for prefix, fn in self.handlers:
            if tuple(argv[: len(prefix)]) == prefix:
                return fn(argv, None).returncode
        return 0

    def spawn_detached(self, argv, *, env=None) -> int:
        self.detached_calls.append(list(argv))
        return 4242

    def argvs(self) -> list[list[str]]:
        return [argv for argv, _ in self.calls]
