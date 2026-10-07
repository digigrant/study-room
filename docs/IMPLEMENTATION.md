# Implementation notes

How the code maps to [SPEC](SPEC.md), and the places where an implementation constraint required a concrete refinement. None of them weakens a trust boundary.

## Map

| SPEC | Where |
| --- | --- |
| 5, 16.1 host detection and setup | `studyroom/hostdetect.py`, `studyroom/setup.py`, fixtures in `tests/fixtures/hosts/` |
| 8 Obsidian | `studyroom/obsidian.py` |
| 9 sandbox and workspace | `studyroom/entry.py`, `sandbox/bin/study-room-configure.ts`, `sandbox/bin/study-room-entry.ts` |
| 10 Learn | `sandbox/bin/fetch-upstream.sh`, `sandbox/bin/verify-checkout.sh`, `sandbox/lib/profile.ts` (`learnResources`) |
| 11 researcher | `sandbox/lib/policy.ts`, `sandbox/lib/closure.ts`, `sandbox/lib/panes.ts`, `sandbox/extensions/study-room-guard/` |
| 12 research tools | `sandbox/lib/url-policy.ts`, `sandbox/lib/fetcher.ts`, `sandbox/lib/extract.ts`, `sandbox/extensions/web-fetch/` |
| 13 network | `studyroom/network.py`; host egress guard: `host/sbx-egress-guard`, `studyroom/egress.py`, `tests/egress/functional.sh` |
| 14 model profiles, thinking | `studyroom/config.py`, `sandbox/lib/thinking.ts` |
| 15 credentials | `studyroom/oauth/`, `studyroom/resolver.py`, `studyroom/infisical.py`, `studyroom/keyring.py`, `studyroom/redact.py` |
| 17 lock | `lock/study-room.lock.json`, `studyroom/lock.py`, `sandbox/Dockerfile` |
| 18 updates | `studyroom/updates.py`, `studyroom/bump.py` |
| 19 commands | `studyroom/cli.py` |
| 20 testing | `tests/host/`, `sandbox/tests/`, `studyroom/testrunner.py`, `studyroom/verify.py`, `studyroom/receipts.py`, `sandbox/bin/study-room-live-check.ts`, `sandbox/extensions/verification-budget/` |
| 21 failures | `studyroom/errors.py` |

## Refinements

**`/workspace`.** Docker Sandboxes mounts a workspace at the same absolute path it has on the host. It has no option to mount it elsewhere. The root-only configure step therefore creates `/workspace` as a symlink to that mount, and Pi starts in `/workspace`. Only `Study Room/` is mounted either way.

**Sandbox image.** Docker Sandboxes runs local images as templates (`sbx template load`, `sbx create --template … shell <path>`). The image starts from the digest-pinned `docker/sandbox-templates:shell-0.7.0`, which provides the `agent` user, the proxy CA handling and sudo. The image is built locally with Docker and loaded; it is never published.

**Node.js 22.23.3.** SPEC 17 records 22.22.1 as the observed baseline and puts the final pin in the lock. The lock pins 22.23.3, the latest 22.x (Jod LTS) patch release when this was written, which includes the security releases since 22.22.1. Pi 1.0.0 needs Node 22.19 or later.

**npm tree digest.** Pi 1.0.0 ships an `npm-shrinkwrap.json` whose seven `@earendil-works/*` entries have no integrity values, and `npm ci` does not enforce the root lockfile's integrity inside that subtree. This was confirmed: a deliberately wrong value installed without error. The lockfile carries registry integrity for those entries anyway. The lock also records a SHA-256 digest of the entire installed `node_modules` tree (`sandbox/bin/tree-digest.mjs`); the image build recomputes it and fails on any difference. The digest was confirmed identical across clean installs.

**Pi peer dependencies.** `sandbox/runtime/.npmrc` sets `legacy-peer-deps=true`. Pi supplies `pi-ai`, `pi-tui` and `typebox` to extensions through its module map; physical copies of those packages would bypass it.

**OpenAI provider.** Pi 1.0.0 has two ChatGPT paths. The legacy `openai-codex` provider decodes the access token as a JWT to find the account, which an opaque placeholder cannot satisfy. Study Room uses the `openai` provider with "Sign in with ChatGPT" (issued client, `chatgpt.tokens.use.direct` scope), which sends the token as a plain bearer to `api.openai.com/v1`. The sandbox sets `OPENAI_API_KEY` to the placeholder. Docker Sandboxes' own `sbx secret set openai --oauth` is not used (SPEC 15.4).

**Thinking levels.** Effective levels are computed with the same algorithm as pi-ai's `clampThinkingLevel`. A test compares the two for every model and level in the pinned OpenAI and Kimi catalogs. Entry refuses a main model that cannot honour `max` unless `profiles.main.thinking_fallback` is set.

**Researcher lifecycle.** pi-interactive-subagents learns that a run ended by reading the exit sentinel from its tmux pane. If the pane is closed first, the package waits forever. The guard watches tracked runs. When a researcher process disappears without a result, the guard reports it through the package's own `.exit` sidecar after a grace period. Orphans are cleaned at the next main-session start, and running researchers are stopped when the parent quits.

**Live-check limits.** A Pi extension that throws from `before_provider_request` does not cancel the request. A hermetic test proved this: a looping run sent thousands of requests to the fake provider. The verification-budget extension therefore blocks and terminates tool calls once the last allowed turn is used, and exits the process before any over-budget request is sent.

**Infisical storage (captain's decision, 2026-10-06).** SPEC 15.2 describes a per-host path, `/study-room/oauth/<provider>/<installation-id>`, with a path-scoped grant. Infisical's Free plan cannot scope grants by path. The captain decided the OpenAI token lives in the existing Agents project, in the `OPENAI_REFRESH_TOKEN` secret. To keep per-host independence, its value is a document with one entry per installation ID:

```json
{"kind": "study-room-oauth", "schema": 1, "provider": "openai", "installations": {"<installation-id>": {"access": "…", "refresh": "…", "expires_ms": 0, "client_id": "…", "generation": 3}}}
```

- A host merges only its own entry into the latest document, writes it back, and reads it back twice. If another host's simultaneous write dropped the entry, it merges again.
- Writes use the v4 secrets API; a "change approval" response is treated as a failure, not a write.
- The client refuses to write any secret other than the configured OAuth secrets.
- A value Study Room did not write (for example a token pasted by hand) is never used, and is replaced only after confirmation in `study-room auth`.

**Host egress guard (captain's decision, 2026-10-06).** Docker Sandboxes ends sandbox traffic in gVisor's userspace netstack inside its host daemon. The sbx 0.46.0 binary carries gVisor's `tcpip/stack` and its TCP `Forwarder`, and has no host bridge or `DOCKER-USER` handling. So the guard matches the daemon process, by the cgroup of its managed systemd user unit, not a network segment.

- **Why iptables-nft's xtables cgroup match, not nftables' native `socket cgroupv2`:** the current WSL2 kernel (`linux-msft-wsl-6.6.y`, `config-wsl`) has `# CONFIG_NFT_SOCKET is not set`. It does build `CONFIG_NETFILTER_XT_MATCH_CGROUP` and `CONFIG_NFT_COMPAT`, and so do Ubuntu's kernels. The rules still land in the nftables ruleset.
- **Reload at every start:** a cgroup match binds to the cgroup present at load time. The unit therefore reloads the guard in `ExecStartPre`, which runs inside the new cgroup. The functional test shows that without the reload, a restarted daemon is not covered.
- **Where it was tested:** the functional test runs on this repository's development VM, whose kernel has the xtables cgroup match but not `NFT_SOCKET`. The WSL2 and native kernels are checked live.

**Kimi catalog endpoint.** `study-room models kimi` calls `https://api.kimi.com/coding/v1/models`. That endpoint is not verified and is used only on explicit request.

## Running the tests

```bash
bin/study-room test --build          # host suite + sandbox suites in the image, network disabled
bin/study-room test --only host      # Python only
bin/study-room test --only egress    # the egress guard on real netfilter (needs privileged Docker)
STUDY_ROOM_NODE=/path/to/node22 bin/study-room test --only host   # also cross-checks the profile contract in TypeScript
```
