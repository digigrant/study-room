# study-room

A reproducible Docker Sandbox study environment built around Pi, a graphical Obsidian Sync vault, and a researcher subagent.

Pi teaches with the unmodified [Learn](https://github.com/amosblomqvist/learn) `teach` skill, quizzes and questions, and an `md-log` lesson log. A `researcher` subagent (from the pinned [pi-interactive-subagents](https://github.com/amosblomqvist/pi-interactive-subagents)) verifies facts with web search, a hardened `web_fetch`, and `safe_bash`. Pi runs in a Docker Sandbox that sees only the vault's `Study Room/` folder; Linux Obsidian Desktop on the host shows the same files and keeps them in Obsidian Sync. Real provider and GitHub credentials stay on the host: the sandbox holds placeholders that Docker Sandboxes' proxy swaps for short-lived values.

- [Specification](docs/SPEC.md): the design baseline this implements.
- [Setup runbook](docs/SETUP.md): a fresh Ubuntu 24.04 host (native Desktop or WSL2) to a first lesson.
- [Security model](docs/SECURITY.md): what is protected, what is not, and the accepted risks.
- [Live acceptance](docs/ACCEPTANCE.md): the checks that need real hardware, accounts and credentials.
- [Implementation notes](docs/IMPLEMENTATION.md): how the code maps to the specification, and where it had to refine it.

## Quick start

```bash
git clone https://github.com/digigrant/study-room.git ~/study-room
~/study-room/bin/study-room setup          # shows every host change and asks first
~/study-room/bin/study-room models openai  # the authenticated catalog
~/study-room/bin/study-room config set profiles.main.model <model-id>
~/study-room/bin/study-room run
```

## Commands

| Command | What it does |
| --- | --- |
| `study-room setup [--yes]` | Detect the host, show the exact changes, apply only approved ones, then run the interactive ceremonies (Docker sign-in, Infisical handles, Obsidian Sync, provider sign-in). `--yes` approves host changes, never ceremonies. |
| `study-room doctor` | Report host, configuration and sandbox readiness. Changes nothing. |
| `study-room auth openai\|kimi` | Authorize a provider on this host; the state goes to this host's Infisical path. Kimi stays experimental. |
| `study-room models openai\|kimi` | List the authenticated model catalog. |
| `study-room obsidian setup` | Guide the fresh Linux vault replica and Sync onboarding, then verify it. |
| `study-room network balanced\|web` | Switch the sandbox-scoped network mode (`web` asks for typed confirmation). |
| `study-room run [--no-obsidian]` | Start or reuse Obsidian, prepare the sandbox, and enter the tmux/Pi session. |
| `study-room test [--build]` | Hermetic tests: no credentials, providers, GitHub mutations or vault. |
| `study-room verify --live [provider\|research\|github\|obsidian\|infisical]` | Explicit, consented, bounded live checks with the cheap verification model. |
| `study-room check-updates [--refresh]` | Dependency drift. Installs nothing. |
| `study-room bump <dependency>` | Move one pin on a branch, rebuild from scratch, rerun the tests. |
| `study-room destroy` | Remove the sandbox and its disposable state. Keeps the vault and host configuration. |
| `study-room config show\|get\|set` | Inspect or change trusted host configuration. |

## Repository layout

| Path | Contents |
| --- | --- |
| `bin/study-room`, `studyroom/` | Trusted host command (Python 3.12+, standard library only). |
| `lock/study-room.lock.json` | Every pin and integrity value. Builds fail on any mismatch. |
| `sandbox/` | Sandbox image (`Dockerfile`), pinned npm runtime, Pi extensions (`study-room-guard`, `web-fetch`, `verification-budget`), entry scripts and the sandbox test suites. |
| `tests/host/`, `tests/fixtures/` | Hermetic host tests and host-capability fixtures. |

Learn is never copied into this repository: the image clones it at the pinned commit and loads the approved resources in place.
