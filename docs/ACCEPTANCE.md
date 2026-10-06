# Live acceptance

The hermetic suite (`study-room test --build`) proves the logic with fakes. It cannot prove native KVM, Docker Sandboxes' microVM and proxy behaviour, desktop keyring integration, graphical Obsidian, or real provider access (SPEC 20.5). This page lists what must be run on real hosts with real accounts, the commands to run, and the expected results. V1 is complete only when these pass on both platforms.

## Gates

These items from SPEC section 26 need something only available on a real host. Their status in this implementation:

| Gate | Built and tested hermetically | Still needed live | Open decision |
| --- | --- | --- | --- |
| Infisical permissions for `sbx-host` | Writes limited to the configured OAuth secrets; per-installation entries; concurrent-host merge; the `verify --live infisical` check | Grant write, then run the check on the Agents project | Decided 2026-10-06: see [Infisical scope](#infisical-scope) |
| OpenAI OAuth refresh and atomic rotation | PKCE flow, rotation, host lock, write-back and read-back, conflict detection, redaction | `study-room auth openai`, then a session lasting past one token expiry | |
| Pin the OpenAI runtime and verification model IDs | Catalog listing, lock bump to `pinned`, `verify` refuses unpinned models | `study-room models openai`, choose, `study-room bump verification-model openai <id>` | Your model preference |
| Hardened `web_fetch` | Full security contract, with local servers and a fake proxy | A fetch through the real sandbox proxy in both modes | Yes: see [DNS in `web` mode](#dns-in-web-mode) |
| Subagent package unmodified on the pinned Pi/Node | Its own 148 unit tests pass unmodified; tmux lifecycle with real Pi processes | | |
| Placeholder scoping for provider and GitHub requests | Pi sends the placeholder as the bearer; the checks refuse non-placeholder values | `verify --live provider github` | |
| Graphical Obsidian launch and readiness (WSLg, native) | Vault checks; launch or reuse logic | `study-room run`; `verify --live obsidian` | |
| Native Ubuntu hardware acceptance | Capability fixtures for native and WSL2 | The full procedure below on Ubuntu Desktop 24.04 x86_64 | |
| Kimi credentials | Device flow, rotation, capability gating, banner label | `study-room auth kimi`, then the Kimi checks | |

### Infisical scope

**Decided by the captain on 2026-10-06.** The OpenAI token is kept in the existing Agents project, in the secret `OPENAI_REFRESH_TOKEN` the captain created. No Infisical Pro upgrade and no separate project.

Consequences:

- `sbx-host` needs write access in the Agents project. On the Free plan this is project-wide, because path-scoped grants need a paid plan. Study Room's client writes only the configured OAuth secrets.
- One secret serves every host. Its value holds one entry per installation ID, so each host still rotates independently (SPEC 15.2).

Live steps:

1. Give `sbx-host` a role that can write in the Agents project's `dev` environment.
2. Run `study-room verify --live infisical`. Expected: the GitHub token is readable, and `OPENAI_REFRESH_TOKEN` is readable and writable.
3. Run `study-room auth openai`. If the secret currently holds a hand-entered value, confirm its replacement.

### DNS in `web` mode

Inside Docker Sandboxes, DNS resolution happens in the host-side proxy, so `web_fetch` cannot pin the resolved address the way it does outside a sandbox. Docker Sandboxes does not apply CIDR denies to host names. In `web` mode, a public name that resolves to a private address could therefore reach a LAN or host service on port 80 or 443. `balanced` mode is unaffected, because only allowlisted domains resolve.

Options:

- (a) accept this as a documented residual risk of `web` mode (current behaviour, shown in the banner and in SECURITY.md);
- (b) disable `web` mode until Docker Sandboxes enforces address checks on resolved names;
- (c) add a best-effort DNS-over-HTTPS pre-check, which needs one more allowlisted destination and still leaves a time-of-check gap.

## Procedure (run on WSL2 and on native Ubuntu Desktop 24.04)

1. **Fresh host.** No Pi and no Obsidian installed. `study-room setup`. Expected: every change is listed before anything runs, and declining a required change stops setup with "permission declined". After the re-login, a second `study-room setup` reports "No host changes are needed."
2. **Doctor.** `study-room doctor --host-only`. Expected: every line is `ok` except the live-check warnings.
3. **Infisical access.** `study-room verify --live infisical`. Expected: `GITHUB_GEJ_MACHINE_PAT` readable; `OPENAI_REFRESH_TOKEN` readable and writable.
4. **Obsidian.** `study-room obsidian setup` against the existing remote vault. Expected: "Obsidian vault ready". The Windows vault directory is not used.
5. **OpenAI.** `study-room auth openai`, then `study-room models openai`. Choose the runtime model (`config set profiles.main.model`) and pin the cheap verification model on a branch (`study-room bump verification-model openai <id>`).
6. **Entry.** `study-room run`. Expected:
   - the banner shows the platform, `Network mode: balanced`, and the main and researcher models with requested and effective thinking;
   - Pi starts in tmux in `/workspace`; `!pwd` prints the resolved path of the vault's `Study Room/` directory, which is mounted at the same path it has on the host;
   - `!ls /workspace/..` shows no `.obsidian`.
7. **Pi sees only `Study Room/`.** Ask Pi to write `hello.md` in `/workspace`. Expected: it appears in Obsidian within seconds. `study-room-diagnose` inside the sandbox reports "only Study Room/ is mounted" and "vault paths are not Git repositories".
8. **Researcher.** Ask Pi to have the researcher check a fact. Expected:
   - a right-hand tmux pane runs the researcher with `web_search`, `web_fetch` and `safe_bash`;
   - the result returns to the teacher with source URLs;
   - asking for a `scout` or a different model is refused by "Study Room policy".
9. **Placeholders.** In the sandbox, `echo $OPENAI_API_KEY` shows `sr-openai-…`. Run `study-room verify --live provider research github`. Expected:
   - each check discloses its model, thinking level, limits and timeout, and runs only after you type `yes`;
   - `placeholder`, `provider`, `research` and `github` all pass;
   - a receipt appears under `~/.local/state/study-room/receipts/`.
10. **Network modes.**
    - In `balanced` mode, ask the researcher to `web_fetch` a page on a domain outside the allowlist. Expected: "the sandbox network policy blocked …".
    - `study-room network web` (type `web`). The banner shows `web` at the next entry, and the same fetch succeeds.
    - Fetching `http://192.168.1.1/` or `http://host.docker.internal/` is refused in both modes.
11. **Obsidian scratch note.** `study-room verify --live obsidian`. Expected: the note is visible in the sandbox, opens in Obsidian, and is deleted afterwards.
12. **Remote Sync (one time, manual).** Create a note in `Study Room/` from Pi. Confirm it appears on a second Obsidian client (for example Windows), edit it there, and confirm the edit returns.
13. **Refresh.** Leave a session open past the access-token lifetime. Expected:
    - requests keep working;
    - this host's entry in `OPENAI_REFRESH_TOKEN` increments its generation by exactly one per refresh, and the other host's entry is untouched;
    - two `study-room resolve openai` runs at once do not both refresh.
14. **Drift.** `study-room check-updates --refresh` lists newer upstream versions without installing anything. The banner shows a concise warning.
15. **Destroy.** `study-room destroy --yes`. Expected: the sandbox is gone; `Study Room/` and `~/.config/study-room/` are intact; the next `study-room run` recreates the sandbox.
16. **Logs.** Search `~/.config/study-room`, `~/.local/state/study-room`, `~/.cache/study-room`, the vault and this checkout for each live token value, passed to `grep -F -f -` on stdin. Expected: no matches.
17. **Delivery.** Ask Pi to clone a repository, push a branch and open a pull request with the `gej-machine` token. Expected: it works without merging anything or changing any setting.

## Kimi (when credentials are available)

`study-room auth kimi`, `study-room models kimi`, pin the Kimi verification model, then `study-room config set providers.kimi.enabled true` and `study-room verify --live --provider kimi provider research`.

Kimi stays labelled experimental until model discovery, refresh, effective thinking (Pi maps `medium` up to `high` for Kimi models, which the banner shows), search and source handling, researcher lifecycle, and error handling have all passed.
