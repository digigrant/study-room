# Study Room Specification

**Status:** Design baseline; implementation has not started

**Primary targets:** x86_64 Ubuntu Desktop 24.04 LTS and x86_64 Ubuntu 24.04 under WSL2

**Repository:** <https://github.com/digigrant/study-room>

## 1. Purpose

Study Room is a reproducible Docker Sandbox environment for interactive learning with Pi and a graphical Obsidian Sync vault. It combines:

- Pi as the primary teacher;
- the selected, unmodified teaching resources from Amos Blomqvist's `learn` repository;
- interactive quizzes and questions;
- an asynchronous researcher subagent;
- grounded web search and bounded source retrieval;
- a Linux Obsidian Desktop companion displaying the same study files Pi edits;
- OpenAI as the initially required, verified provider path;
- a capability-gated Kimi provider path;
- host-side credential resolution that does not expose real credentials to the agent sandbox.

Accuracy and teaching quality take priority over model cost during normal study sessions. Connectivity tests are a separate exception: they must use an inexpensive model, low reasoning effort, short prompts, and hard request/output limits.

## 2. Normative language

`MUST`, `MUST NOT`, `SHOULD`, and `MAY` are normative requirements.

The checked-in implementation, lock data, and acceptance tests must refine this specification without silently weakening its trust boundaries. If an implementation constraint conflicts with this specification, setup must fail clearly or the specification must be reviewed and changed first.

## 3. Goals

V1 MUST provide:

1. A fresh-host setup path for both supported platforms.
2. Deterministic, reviewable dependency pins.
3. A graphical Linux Obsidian Desktop client with Obsidian Sync onboarding.
4. Read-write Pi access to only the vault's `Study Room/` subtree.
5. Pi with standard tools inside the Docker Sandbox.
6. The core Learn teaching loop: `teach`, `quiz`, `ask_user_question`, and `md-log`.
7. One permitted subagent role: `researcher`.
8. A configurable researcher model with `medium` thinking by default.
9. Research tools consisting of provider-backed `web_search`, hardened `web_fetch`, and the selected subagent package's `safe_bash`.
10. OpenAI authorization and refresh managed outside the untrusted sandbox.
11. A capability-gated Kimi authorization/configuration path.
12. GitHub branch and pull-request workflows using the existing `gej-machine` classic PAT.
13. Entry-time dependency-drift notifications without automatic upgrades.
14. Hermetic tests plus explicitly invoked, inexpensive connectivity checks.
15. Disposable Pi and researcher sessions; durable intentional Markdown notes.

## 4. Non-goals

V1 does not include:

- visualization agents;
- Mermaid or SVG generation;
- Chrome, Puppeteer, Mermaid CLI, or browser rendering infrastructure;
- a headless Obsidian-only workflow;
- Obsidian Headless operating on the Desktop client's local replica;
- a Git repository in the Obsidian vault;
- durable Pi transcript/session storage across sandbox destruction;
- a custom `/study` command;
- automated teaching-quality benchmarks;
- scheduled dependency-checking automation;
- automatic dependency upgrades;
- automatic PR merges;
- repository administration or security-setting changes by an agent;
- support for ARM hosts;
- support for a headless Ubuntu Server host;
- Windows-side provisioning of WSL itself;
- shared-infrastructure extraction from `devenv`;
- immediate shared-code extraction into `sandbox-foundation`;
- publication of locally built images containing upstream checkouts.

## 5. Supported host boundary

### 5.1 Native Ubuntu

V1 MUST support x86_64 Ubuntu Desktop 24.04 LTS from the first release. The host must provide:

- a local Wayland or X11 graphical session;
- systemd and a systemd user session;
- WSL-independent KVM support;
- sudo access for approved host changes;
- a Secret Service-compatible keyring;
- outbound network access for installation, authentication, Sync, providers, and GitHub.

Headless Ubuntu Server is excluded because it cannot satisfy the required graphical Obsidian workflow without adding remote-desktop infrastructure.

### 5.2 WSL2

V1 MUST support an x86_64 Ubuntu 24.04 WSL2 distribution on Windows 11 with:

- systemd enabled;
- WSLg available for Linux GUI applications;
- working KVM support for Docker Sandboxes;
- sudo access inside the distribution.

The fresh-host boundary begins inside an existing supported Ubuntu WSL2 distribution. Creating or enabling WSL from Windows, changing Windows firmware, and provisioning Windows itself are documented prerequisites, not automated V1 operations.

### 5.3 Capability detection

Setup MUST detect capabilities rather than relying on hard-coded Windows paths or a broad `is WSL` branch. The same XDG-oriented layout and commands should be used on both platforms. Platform-specific behavior is limited to real differences such as WSLg versus native Wayland/X11 integration.

The implementation MUST NOT depend on `C:\Users\...` or mount the existing Windows Obsidian directory.

## 6. Trust model

### 6.1 Trusted host components

The following run outside the agent sandbox and are trusted:

- the `study-room` host command and setup code;
- Docker Sandboxes and its credential proxy;
- the project-owned provider authorization/refresh resolver;
- Infisical access using the `sbx-host` machine identity;
- the host keyring namespace owned by Study Room;
- Linux Obsidian Desktop and its local vault replica;
- the trusted infrastructure checkout of this repository.

Trusted host code MUST NOT be writable through a sandbox mount.

### 6.2 Untrusted sandbox components

The following are treated as untrusted with respect to host credentials and host files:

- the main Pi agent;
- the researcher child process;
- model-generated commands;
- content returned by websites;
- Learn extensions and skills;
- third-party Pi extensions;
- repositories cloned during a study session.

The sandbox boundary protects the host outside intentionally shared mounts. It does not protect files intentionally mounted into the sandbox.

### 6.3 Exposed data

The main sandbox receives read-write access to the vault's `Study Room/` directory. It MUST NOT receive the full vault, `.obsidian`, Obsidian account state, Obsidian encryption material, Infisical credentials, provider refresh tokens, or real provider access tokens.

The sandbox may contain disposable clones and temporary artifacts that disappear when it is destroyed.

### 6.4 Accepted consequences of shell access

The main Pi process has standard Pi tools, including bash.

The researcher is also explicitly granted the `safe_bash` tool at the user's direction. The bundled `safe_bash` is a blacklist around ordinary bash, not an operating-system sandbox or an allowlisted command runner. It blocks a small set of conspicuously destructive command patterns but still permits reading, writing, deleting, processing, and transmitting files visible inside the sandbox.

Consequently:

- the researcher can use shell commands to inspect or alter `Study Room/`;
- it can delete relative files even though host-wide destructive patterns are blocked;
- it can invoke interpreters and network clients;
- in broad-web network mode it can transmit study-note content to arbitrary public HTTP(S) destinations;
- it can see proxy placeholder values, though never the real substituted secrets;
- if GitHub command-line authorization is usable from the same process environment, shell access may exercise that delegated GitHub authority.

These are accepted V1 risks. `safe_bash` MUST NOT be described as a strong security boundary. Docker Sandbox still protects host files outside the mount and keeps real credentials host-side.

Obsidian Sync version history is a recovery mechanism, not a prevention mechanism.

## 7. High-level topology

```text
Ubuntu host (native or WSL2)
├── trusted study-room checkout
├── trusted authorization/refresh resolver
│   ├── host keyring: installation metadata / machine identity handle
│   └── Infisical: per-host rotating provider state
├── Docker Sandboxes credential proxy
│   └── substitutes real short-lived credentials for scoped placeholders
├── Linux Obsidian Desktop
│   ├── account and Sync credentials
│   ├── .obsidian and encryption state
│   └── full local vault replica
│       └── Study Room/  <────────────┐
└── Docker Sandbox                    │ same files
    ├── /workspace  ──────────────────┘
    ├── Pi main teacher
    ├── tmux researcher child
    ├── read-only pinned upstream checkouts
    ├── proxy placeholders only
    └── ephemeral sessions, artifacts, and repository clones
```

## 8. Obsidian architecture

### 8.1 Desktop is authoritative locally

A trusted, project-provisioned Linux Obsidian Desktop process owns the complete local vault replica and Obsidian Sync. Pi and Obsidian operate on the same underlying `Study Room/` files so Pi's changes are visible graphically without an intermediate synchronization step.

Obsidian MUST NOT run inside the Pi Docker Sandbox.

### 8.2 Fresh Linux replica

Each host creates a fresh Linux local replica from the existing remote Obsidian Sync vault. It MUST NOT reuse or mount the Windows local vault directory.

A default location may follow the XDG data directory, for example:

```text
${XDG_DATA_HOME:-$HOME/.local/share}/study-room/obsidian-vault
```

The actual path is configurable and recorded in trusted host configuration. Paths MUST NOT be hard-coded to a username or Windows drive.

Windows Obsidian may remain a separate Sync client using its own local directory.

### 8.3 Desktop versus Headless

Obsidian Headless is not part of the selected V1 topology. Desktop and Headless MUST NOT manage the same local replica concurrently. No Headless token or configuration directory is mounted into the Pi sandbox.

### 8.4 Installation and authorization

Setup MUST install a pinned Linux Obsidian Desktop artifact after explicit user approval. It MUST verify the artifact checksum and MUST NOT silently substitute the latest release.

Obsidian account login, Sync login, encryption-key entry, and remote-vault selection remain interactive user ceremonies. Setup must explain each step and then verify the configured local vault and `Study Room/` directory exist.

### 8.5 Normal entry

`study-room run` SHOULD:

1. validate host readiness;
2. start or reuse Obsidian Desktop with the configured vault;
3. create or attach to the Study Room sandbox;
4. enter the tmux/Pi session with `/workspace` mapped to `Study Room/`.

`--no-obsidian` MAY skip the GUI for maintenance or troubleshooting. Normal entry does not restart a healthy Obsidian process.

### 8.6 Active lesson-log editing rule

The upstream `md-log` extension reads and rewrites the whole target note. It cannot safely coordinate with a simultaneous Obsidian edit.

The supported workflow is:

1. create a new, empty, dedicated lesson-log note;
2. invoke `/md-log <path>`;
3. view, but do not edit, that note in any Obsidian client while logging is active;
4. edit other notes normally;
5. invoke `/md-unlog` or end the session before editing the lesson log.

This is an operational rule, not a technically enforced lock. Linking a nonempty note or editing the active note concurrently risks overwritten content.

## 9. Sandbox and workspace

### 9.1 Host mount

Only the host's `Study Room/` directory is mounted read-write as the sandbox workspace. The full vault and trusted infrastructure checkout MUST NOT be mounted.

The vault MUST NOT be initialized as a Git repository. No nested upstream clone may be placed in it.

### 9.2 Main Pi tools

The main session receives standard Pi tools, including read, write, edit, and bash, plus the selected study extensions and subagent tools. It may run examples and clone repositories into disposable sandbox-local storage.

### 9.3 Sessions

Pi main-session history, researcher child sessions, tmux artifacts, loadout snapshots, and temporary repositories are disposable in V1. They remain outside Git and outside the Obsidian vault.

Removing the sandbox may remove all such state. Intentional Markdown written into `Study Room/` remains durable through the host replica and Obsidian Sync.

### 9.4 Upstream source inside the sandbox

Pinned upstream checkouts live outside `/workspace`, under a location such as:

```text
/opt/study-room/upstream/
```

They are root-owned/read-only during normal use. They are not host infrastructure checkouts and are not durable user data.

## 10. Learn integration

### 10.1 Source relationship

Study Room consumes Learn as an unmodified, pinned upstream checkout. It does not vendor, copy into this repository, fork, or patch Learn in V1.

Initial pin:

```text
repository: https://github.com/amosblomqvist/learn.git
commit:     7cfd8942f82ab9476e63572387e1fe9bcea5082c
```

The deterministic build MUST:

- clone that exact commit directly from upstream;
- verify the remote URL, commit, expected tree/checksum, and clean worktree;
- fail rather than move to another commit;
- leave the checkout unmodified;
- make it read-only for normal execution.

This repository records only provenance, pin, integrity data, and resource-selection configuration.

Learn currently declares no repository license. Because V1 does not vendor or publish a derivative copy, the immediate implementation does not depend on committing its source here. Any future fork, vendoring, patch distribution, or image publication MUST revisit licensing and attribution first.

### 10.2 Loaded resources

The following resources are loaded directly from the checkout:

- `skills/teach/`
- `extensions/ask-user-question.ts`
- `extensions/quiz.ts`
- `extensions/md-log.ts`

The following are not loaded in V1:

- `skills/visualize/`
- `extensions/visual-tools/`
- Learn's `researcher.md` agent definition;
- `svg-maker.md`;
- `mermaid-maker.md`.

Pi settings or explicit paths MUST select only the approved resources rather than copying them elsewhere.

### 10.3 Compatibility

The initial Pi pin provides virtual aliases for Learn's legacy `@mariozechner/*` imports. Learn therefore loads without a source patch.

If a proposed Pi bump removes that compatibility, the build/update test MUST fail. The resolution is to retain a compatible Pi pin, obtain an upstream-compatible release, or explicitly revisit this specification—not to mutate Learn during a runtime build.

## 11. Researcher subagent

### 11.1 Runtime

The researcher uses the pinned tmux-based `pi-interactive-subagents` implementation:

```text
repository: https://github.com/amosblomqvist/pi-interactive-subagents.git
commit:     c3e8b53c0754ae5ccc19fdab5a7481ec039bc2f7
license:    MIT
```

Its source remains attributable to the upstream MIT project. Compatibility and lifecycle tests may use an external Node invocation appropriate for the pinned Node release; a broken upstream test command is not silently treated as passing.

The child process runs in its own tmux pane, reports status to the parent, returns a sourced brief, exits automatically, and stores only ephemeral session artifacts.

### 11.2 Researcher definition

Study Room supplies an independently authored researcher definition. It does not copy Learn's researcher prose. The definition has:

- one role name: `researcher`;
- a separately configurable provider/model;
- default thinking level `medium`;
- `auto-exit: true`;
- no nested-subagent permission;
- tools `web_search`, `web_fetch`, and `safe_bash`.

The initial researcher model defaults to the configured main provider/model unless the user selects a dedicated one. The researcher setting is independent after initialization.

Thinking is configurable. The UI/entry diagnostics MUST display both requested and effective thinking levels. If a provider does not support `medium`, Pi's advertised mapping/clamping applies and the effective value must be visible. Current Kimi model metadata may map a `medium` request upward to `high`; this must not happen silently.

The main agent MUST NOT be allowed to choose an arbitrary per-call researcher model without policy validation. Spawn-time model overrides that differ from trusted researcher configuration are stripped or rejected unless explicitly authorized by user configuration.

### 11.3 Only one subagent role

The top-level environment sets and enforces an allowlist equivalent to:

```text
PI_SUBAGENT_ALLOWED=researcher
```

Bundled `scout`, `worker`, and any other discovered role are hidden and rejected. The researcher itself cannot spawn children.

This restriction controls which subagent profiles may be launched. It does not constrain commands executed through `safe_bash`.

### 11.4 Lifecycle requirements

Tests MUST cover:

- spawn and successful completion;
- parent continuing while the child runs;
- status updates;
- result steering to the parent;
- cancellation;
- child crash;
- tmux pane closure;
- parent exit;
- orphan cleanup;
- artifact cleanup on sandbox destruction;
- resume preserving the original loadout;
- rejection of non-researcher roles;
- rejection of unapproved model overrides.

## 12. Research tools

### 12.1 Web search

The initial search implementation is pinned to:

```text
package: pi-web-search@1.6.0
repository commit inspected: 66e14d30be2fc4b56ef4a0f77efd55cd81f1b5c4
package license metadata: MIT
```

The exact npm tarball integrity is stored in the lock data. Search uses provider-native grounded-search facilities and returns source URLs/citations.

OpenAI-backed search may use a dedicated configured search model even when the teaching model differs. A deployment must not silently start using another credential or billable model; dedicated search configuration is explicit.

Kimi native search remains unverified. Kimi is not promoted from experimental until search and source handling pass live capability checks. If Kimi cannot provide grounded search, a Kimi teaching profile may require a separately configured OpenAI search credential; that is not described as Kimi-only support.

### 12.2 Hardened web fetch

V1 provides a project-owned or separately pinned MIT `web_fetch` implementation satisfying this contract:

- accept only public HTTP or HTTPS URLs;
- reject URL credentials;
- reject loopback, private, link-local, multicast, metadata-service, and special-use destinations for IPv4 and IPv6;
- safely resolve DNS and prevent DNS-rebinding/time-of-check-time-of-use bypasses;
- manually follow a small bounded number of redirects;
- revalidate destination and DNS at every hop;
- reject unsupported protocols and HTTPS-to-HTTP downgrade redirects;
- send no cookies, authorization, Infisical data, provider tokens, or GitHub tokens;
- use no persistent browser profile;
- execute no page JavaScript;
- enforce connection, total-operation, response-byte, extracted-text, and PDF-page limits;
- accept only supported textual/HTML/PDF content;
- return bounded, clearly attributed content and final URL;
- treat fetched content as untrusted model input;
- write overflow data only to sandbox-ephemeral storage, never the vault;
- clean temporary data at session/sandbox teardown.

The default hardened fetch may reach arbitrary public hosts only when Docker's selected network mode permits them. Under balanced mode, Docker's domain policy remains the outer restriction.

An unrestricted or browser-backed fetch implementation is not included by default. Replacing the hardened implementation is an explicit future configuration/design change.

Because `safe_bash` can invoke network clients, hardened `web_fetch` is a safer default interface and quality control, not a complete egress boundary.

### 12.3 Safe bash

The researcher loads the `safe_bash` extension from the pinned subagent implementation. Its limitations described in the trust model are part of the accepted design.

No documentation or UI may imply that its command blacklist prevents vault access, exfiltration, relative deletion, interpreter use, or arbitrary commands generally.

## 13. Network policy

### 13.1 Shared policy limitation

Docker Sandbox network rules apply to the complete sandbox, not separately to the main and researcher processes. V1 does not create a second researcher sandbox merely to obtain a different network policy.

### 13.2 Modes

Study Room supports two explicit sandbox-scoped modes:

#### `balanced` (default)

- Docker's balanced policy baseline;
- explicit provider, GitHub, package-registry, and required service destinations;
- provider-mediated web search and URL analysis;
- direct `web_fetch` succeeds only for destinations allowed by policy.

#### `web`

- the balanced baseline;
- sandbox-scoped arbitrary public HTTP(S) egress on TCP 80/443;
- no global `allow-all` policy;
- the main agent, researcher, and shell commands all receive the same expanded egress.

The entry banner MUST display the active mode. Changing mode is an explicit trusted-host operation. Setup MUST NOT overwrite an existing global Docker policy without showing the change and receiving approval.

### 13.3 Accepted broad-mode risk

In `web` mode, either agent can send mounted study data to an arbitrary public web destination. The hardened fetch tool does not prevent `safe_bash` from using another client. Users select this mode for research breadth with that trade-off visible.

## 14. Provider model policy

### 14.1 Deployment contract

A deployment needs at least one operational provider, not subscriptions to every supported provider.

The initial V1 release path requires OpenAI to pass end-to-end connectivity acceptance. Kimi configuration may ship capability-gated and disabled/experimental until authenticated checks pass.

### 14.2 Runtime profiles

Runtime configuration separates:

```text
main.provider
main.model
main.thinking = max

researcher.provider
researcher.model
researcher.thinking = medium

search.provider
search.model

verification.<provider>.model
verification.<provider>.thinking = low
```

Main and researcher thinking levels remain changeable by explicit user configuration; the main Pi session also supports normal per-session changes.

The exact initial production model ID is pinned only after the trusted authorization flow can inspect the authenticated catalog. Selection is based on advertised access/capability and user preference, not an automated quality benchmark. The chosen ID is recorded separately from the cheap verification model.

A main default that does not support `max` cannot be selected without an explicit documented fallback. Requested and effective levels must be visible.

### 14.3 No automated quality judgment

Study Room does not test whether a production model teaches well, whether `max` is worthwhile, or whether `medium` is the best researcher setting. The user judges those properties through normal use and may change the profile.

## 15. Credential architecture

### 15.1 Invariants

The sandbox MUST NOT receive:

- an Infisical machine identity or client secret;
- an Infisical access token;
- a provider refresh token;
- a real provider access token;
- an Obsidian credential;
- Obsidian encryption material;
- the host keyring database.

It receives stable placeholder values. Docker's trusted proxy substitutes real values only for approved destination scopes outside the sandbox boundary.

Secrets MUST NOT be printed, placed in process arguments where avoidable, stored in the vault, stored in Git, or written to sandbox session files.

### 15.2 Infisical

Study Room reuses the existing Infisical project and `sbx-host` machine identity but has independent setup code and a separate namespace.

The identity MUST receive only the narrow read/write scope needed for Study Room provider state, conceptually:

```text
/study-room/oauth/<provider>/<installation-id>
```

It MUST NOT receive project-wide write authority merely for convenience. If the required path scope cannot be enforced, implementation stops for explicit review rather than silently broadening access.

Each host has a random installation ID and independent OAuth state. Hostnames need not be embedded in secret names. Per-host state avoids concurrent refresh-token rotation races across WSL and native Ubuntu installations.

### 15.3 Host keyring

Study Room uses its own keyring service/collection namespace and does not source or call `devenv`. The keyring contains only trusted-host metadata or handles required to use the machine identity; provider refresh tokens remain in Infisical.

Configuration and state follow XDG paths with restrictive permissions, for example:

```text
~/.config/study-room/
~/.local/state/study-room/
~/.cache/study-room/
```

### 15.4 OpenAI

`study-room auth openai` runs in the trusted host component and does not depend on a pre-existing host Pi login.

The trusted component:

1. performs the supported OpenAI/ChatGPT OAuth authorization flow;
2. stores the complete structured OAuth state in the host-specific Infisical path;
3. includes every value needed by the pinned provider implementation, including access token, expiry, refresh token, issued client/client metadata where applicable, and account metadata required for requests;
4. resolves short-lived access tokens for Docker's command-backed secret integration;
5. refreshes under a host-side lock;
6. replaces rotated state atomically;
7. writes a rotated refresh token before releasing the lock;
8. redacts all token-bearing errors and logs.

An approximately 30-day refresh horizon is treated as a reauthorization horizon, not as permission to reuse one unchanged refresh-token string indefinitely.

Docker's native `sbx secret set openai --oauth` is not the selected source of truth because its rotating state lives in Docker rather than Infisical and it does not solve Kimi.

### 15.5 Kimi

`study-room auth kimi` uses a trusted project-owned wrapper around the pinned provider's device authorization flow. Its rotating state follows the same per-host Infisical, locking, atomic replacement, redaction, and placeholder rules.

Expected first-party services include `https://auth.kimi.com` for authorization and `https://api.kimi.com/coding` for the coding provider. Exact endpoint scopes are verified before enabling the profile.

Kimi remains experimental until model discovery, refresh, effective thinking level, search, researcher lifecycle, and error handling pass live connectivity checks.

### 15.6 GitHub

The existing broad/classic `gej-machine` PAT is used for now because the user's fine-grained token path has a blocking limitation.

The token is registered as a Docker-managed placeholder with real substitution outside the sandbox. Agents may:

- clone repositories;
- push branches;
- open pull requests.

Agents MUST NOT, without explicit instruction:

- merge pull requests;
- push directly to protected/default branches;
- alter repository administration;
- alter security settings;
- alter secrets, collaborators, or branch protection.

Because a classic PAT and standard shell are intentionally available, these GitHub restrictions are operating policy rather than a complete technical capability boundary. A narrower token should replace it when the blocking limitation is resolved.

## 16. Host setup

### 16.1 Interactive plan

`study-room setup` MUST:

1. detect OS, architecture, Ubuntu release, WSL2, systemd, display, WSLg/Wayland/X11, KVM, groups, keyring, disk space, and networking;
2. detect Docker and the pinned Docker Sandboxes version;
3. detect Docker login and policy initialization state;
4. detect the pinned Obsidian Desktop installation;
5. detect keyring and Infisical prerequisites;
6. display the exact proposed changes;
7. request permission before sudo, package installation, repository addition, group changes, or policy initialization;
8. perform only approved changes;
9. provide logout/restart instructions when changes cannot take effect immediately;
10. never substitute an unreviewed latest version when a pin is unavailable.

Interactive authentication ceremonies are never bypassed by `--yes`.

### 16.2 Host versus sandbox dependencies

Host applications include:

- Docker and Docker Sandboxes;
- KVM/group support;
- Linux Obsidian Desktop;
- Secret Service/keyring support;
- Infisical access used by the trusted resolver.

Sandbox/image dependencies include:

- exact Node.js and npm releases;
- Pi;
- tmux;
- Git and GitHub CLI;
- selected Learn resources;
- the researcher extension;
- search/fetch integrations;
- entry and test code.

A host Pi installation or host Pi login is neither required nor used.

### 16.3 No `devenv` coupling

`/home/gejoy/devenv` is reference material only. Study Room MUST NOT invoke, source, import, modify, or refactor it.

## 17. Determinism and provenance

A checked-in lock manifest MUST record, as applicable:

- Docker Sandbox version;
- base image digest;
- Node.js version and artifact checksum;
- Pi package versions and npm integrity values;
- exact git remotes and commits;
- npm lockfile integrity;
- Obsidian Desktop version, source URL, architecture, and checksum;
- Infisical CLI/library version if installed;
- system package names and required version constraints;
- test-model IDs and limits;
- expected upstream tree/checksums;
- patch checksums for project-owned patches to licensed dependencies, if any.

Initial known pins/candidates include:

```text
Docker Sandboxes:                 0.46.0
Node.js build baseline observed:  22.22.1 (final artifact pin belongs in lock data)
@earendil-works/pi-coding-agent:  1.0.0
Learn commit:                     7cfd8942f82ab9476e63572387e1fe9bcea5082c
pi-interactive-subagents commit:  c3e8b53c0754ae5ccc19fdab5a7481ec039bc2f7
pi-web-search:                    1.6.0
pi-web-search inspected commit:   66e14d30be2fc4b56ef4a0f77efd55cd81f1b5c4
```

The final lock file, not prose, is authoritative for artifact integrity.

Builds MUST fail on checksum, commit, or integrity mismatch. They MUST NOT mutate source at runtime or turn a failed pin into a latest-version install.

## 18. Updates

Normal entry performs a low-overhead cached drift check. It SHOULD refresh remote metadata no more than once per configurable interval (default 24 hours), use the cached result immediately, and never block entry solely because an update service is unavailable.

The entry banner reports stale pins concisely. It does not install anything.

An explicit bump workflow:

1. discovers candidate versions;
2. shows upstream changes and provenance;
3. updates pins/checksums on a branch;
4. rebuilds from scratch;
5. runs hermetic tests;
6. requires explicitly approved live connectivity checks when relevant;
7. produces reviewable diffs.

There is no scheduled dependency-checking GitHub Action in V1.

## 19. Commands and user experience

The eventual command surface SHOULD include:

```text
study-room setup
study-room doctor
study-room auth openai
study-room auth kimi
study-room obsidian setup
study-room network balanced|web
study-room run [--no-obsidian]
study-room test
study-room verify --live [component]
study-room check-updates
study-room bump <dependency>
study-room destroy
```

Exact spelling may be refined, but responsibilities and trust boundaries remain distinct.

`destroy` MUST preserve the host vault and trusted host configuration by default and ask before deleting anything durable.

Normal entry displays at least:

- platform/readiness summary;
- active network mode;
- configured main provider/model and requested thinking;
- configured researcher provider/model and requested/effective thinking when known;
- configured search provider/model;
- Obsidian readiness;
- stale dependency or stale verification warnings;
- a reminder that an active `/md-log` note is view-only.

## 20. Testing and verification

### 20.1 Hermetic default

`study-room test` uses no real credentials, provider requests, GitHub mutations, or real vault. It covers:

- lock/checksum validation;
- host capability fixtures for WSL2 and native Ubuntu;
- installer planning and idempotency;
- package/resource selection;
- unmodified Learn checkout and clean-tree checks;
- compatibility aliases;
- researcher allowlist and loadout;
- tmux lifecycle with fake providers;
- OAuth parsing, refresh rotation, locking, and atomic write-back with fakes;
- secret redaction and placeholder invariants;
- network policy generation;
- hardened fetch SSRF, redirect, size, timeout, and cleanup behavior;
- vault-mount boundaries;
- update-check caching;
- failure cleanup.

A skipped test is reported as skipped with its reason, never as passed.

### 20.2 Live connectivity

No live verification runs on a schedule or merely because an unchanged sandbox was rebuilt.

Setup may offer a live check only after displaying the exact model, thinking level, maximum request count, maximum output, possible search use, and timeout. It requires explicit confirmation.

Each provider has a separately pinned verification model. Tests MUST:

- use an inexpensive model available through that provider/authentication path;
- use `low` reasoning or no reasoning if that is cheaper and sufficient;
- use a short deterministic prompt;
- set provider-level output limits;
- use ephemeral sessions;
- enforce a request counter and timeout;
- refuse to fall back to the runtime teaching model.

The basic provider check performs one minimal request. Researcher/search connectivity is a separate selectable check with one bounded researcher task and one search invocation. It may make only the minimum model turns required to issue the tool call and return a short cited result.

Live tests prove plumbing, not teaching or research quality. They MUST NOT invoke the runtime default merely to benchmark it, and MUST NOT invoke `max` or the runtime researcher's normal `medium` setting for quality comparison.

### 20.3 Other live checks

Explicit live verification may check:

- Docker placeholder substitution without revealing the substituted value;
- provider connectivity;
- researcher spawn/search/result delivery using the cheap test profile;
- non-mutating GitHub identity and repository access;
- creation and local visibility of a uniquely named scratch note;
- opening that note in Obsidian Desktop;
- scratch cleanup.

Remote Obsidian Sync requires a one-time manual cross-device check. The user verifies a note and edit on a second existing Obsidian client. Headless is not run against the Desktop replica to automate this proof.

### 20.4 Verification receipt

Non-secret receipts live in the trusted host state directory and may record:

- time;
- installation ID;
- configuration/pin fingerprint;
- provider and verification-model IDs;
- vault identity hash;
- checks passed, skipped, or failed.

Entry warns when connectivity has never been checked or a relevant fingerprint changed. It does not claim the runtime model's quality was verified.

### 20.5 Native-host acceptance

Containerized tests cannot prove native KVM, Docker Sandbox microVM behavior, Desktop keyring integration, or graphical Obsidian. V1 native Ubuntu support is not declared complete until the documented live acceptance procedure passes on an actual Ubuntu Desktop 24.04 x86_64 host.

## 21. Failure behavior

Failures MUST be explicit and classified where practical:

- missing host prerequisite;
- permission declined;
- unsupported platform;
- pin/checksum mismatch;
- provider unavailable;
- credentials not configured;
- authorization expired or revoked;
- refresh conflict;
- external service unavailable;
- model absent from authenticated catalog;
- search unsupported;
- network policy blocked destination;
- Obsidian not configured;
- vault path missing;
- subagent crash or timeout.

External outages do not convert hermetic test success into failure. Conversely, hermetic success does not claim live integration success.

No failure path may print a real token or structured secret.

## 22. Repository operation

Implementation work occurs on branches and is submitted through pull requests as `gej-machine`. Agents do not merge automatically.

The trusted host checkout is never mounted read-write into the study sandbox. Runtime agents cannot self-modify host setup code.

Large Pi session files, OAuth state, generated test artifacts, local vault content, and dependency caches are excluded from Git.

## 23. Shared-foundation handoff

Study Room does not refactor `devenv` and does not prematurely extract shared code.

After Study Room is implemented and tested, a documentation-only handoff is added to `digigrant/sandbox-foundation` describing evidence-backed future seams such as:

- Infisical/keyring access;
- Docker Sandbox secret registration;
- host prerequisite checks;
- deterministic update checks;
- common test fixtures;
- security invariants.

Provider bindings, network policy, workspaces, persistence, Obsidian behavior, and entry UX remain project-specific until multiple implemented consumers prove otherwise.

## 24. Deferred work

Deferred items include:

- a Learn fork, if local changes later become necessary;
- licensed upstream resolution if Learn is ever vendored or redistributed;
- visualization agents and rendering dependencies;
- a separate researcher sandbox with an independent network policy;
- a truly constrained research command runner replacing blacklist-based `safe_bash`;
- an unrestricted or browser-backed fetch profile;
- durable/resumable Pi sessions;
- headless-server GUI infrastructure;
- ARM support;
- replacement of the classic GitHub PAT with narrower credentials;
- automated remote Obsidian Sync verification;
- shared implementation extraction into `sandbox-foundation`.

## 25. V1 acceptance criteria

V1 is complete only when all applicable criteria pass:

1. A clean supported WSL2 Ubuntu host can follow the setup runbook without preinstalled Pi or Obsidian.
2. A clean native Ubuntu Desktop 24.04 x86_64 host passes the same acceptance workflow.
3. Host changes are shown and approved before installation.
4. The sandbox rebuilds from locked pins and verified integrity data.
5. Learn remains an unmodified clean checkout at the pinned commit.
6. Only the approved Learn resources load.
7. Linux Obsidian Desktop opens the fresh local Sync replica.
8. Pi sees only `Study Room/` from the host and changes appear in Obsidian.
9. The vault and `Study Room/` are not Git repositories.
10. The main Pi session has the expected study and standard tools.
11. Only the `researcher` subagent profile can be launched.
12. The researcher defaults to configurable `medium` thinking and receives `web_search`, hardened `web_fetch`, and `safe_bash`.
13. Research results include usable sources/citations when the configured provider supports them.
14. OpenAI authorization, refresh rotation, Infisical write-back, locking, and placeholder substitution work without sandbox-readable real credentials.
15. At least one provider is operational; the initial V1 path requires OpenAI.
16. Kimi is clearly labeled experimental until its capability gate passes.
17. Balanced and broad-web modes behave as documented and are visible at entry.
18. Hermetic tests consume no provider tokens.
19. Live tests require explicit consent, use the cheap low-effort profile, and obey hard limits.
20. No automated test claims to measure production teaching quality.
21. Sandbox destruction removes disposable sessions without deleting the host vault.
22. Entry reports stale dependencies without upgrading them.
23. Branch/PR delivery works without automatic merge or repository-administration changes.
24. Security logs and errors contain no real credentials.

## 26. Pre-implementation gates

The following are implementation/prototype gates rather than unresolved product decisions:

- prove the path-scoped Infisical permissions for `sbx-host`;
- prove OpenAI OAuth refresh and atomic rotation through the trusted resolver;
- inspect the authenticated OpenAI catalog and pin the initial runtime and cheap verification model IDs;
- select or implement the hardened `web_fetch` component and pass its security contract;
- prove the subagent package works unmodified with the pinned Pi/Node runtime and external test invocation;
- prove placeholder scoping for provider and GitHub requests;
- prove graphical Obsidian launch/readiness on WSLg and native Ubuntu;
- run native Ubuntu hardware acceptance;
- obtain Kimi credentials before promoting Kimi from experimental.

A failed gate changes implementation status, not the documented result. Any proposed weakening returns to design review.

## 27. Decision summary

- Core teaching plus one researcher is V1; visualization is deferred.
- Learn is cloned at a pin and loaded unmodified; it is not copied into this repository.
- A fresh Linux Obsidian Desktop replica owns Sync; Headless is not used on it.
- Only `Study Room/` is exposed to Pi.
- The main session has standard Pi tools.
- The researcher defaults to `medium`, is configurable, and has `web_search`, hardened `web_fetch`, and `safe_bash`.
- The risks of blacklist-based `safe_bash` inside the shared sandbox are explicitly accepted.
- Balanced networking is default; sandbox-scoped public HTTP(S) is an explicit mode.
- Real credentials remain in trusted host systems; sandbox processes see placeholders.
- OpenAI is the initial verified release path; Kimi is capability-gated.
- Main thinking defaults to `max`; tests use a separate cheap model at `low`.
- Tests verify connectivity and integration, not teaching quality.
- Sessions are disposable; intentional Markdown is durable.
- Pins drift only through an explicit reviewed bump workflow.
- `devenv` remains untouched.
- `sandbox-foundation` receives an evidence-based documentation handoff only after implementation.
