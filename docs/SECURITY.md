# Security model

How Study Room implements the trust model in [SPEC](SPEC.md) sections 6, 12, 13 and 15, and what remains an accepted risk.

## Boundaries

| Trusted (host) | Untrusted (sandbox) |
| --- | --- |
| `study-room` command and this checkout | the main Pi agent and its tools |
| Docker Sandboxes and its credential proxy | the researcher child and `safe_bash` |
| the credential resolver (`study-room resolve`) | model-generated commands, websites' content |
| Infisical access as `sbx-host`; the `study-room` keyring namespace | Learn's extensions and skills, third-party Pi extensions |
| Obsidian Desktop and the full vault replica | repositories cloned during a session |

The sandbox mounts exactly one host path read-write: the vault's `Study Room/` directory. It appears inside at the same absolute path and as `/workspace`. The vault root, `.obsidian`, Obsidian account and encryption state, and this checkout are never mounted. `study-room-diagnose` checks inside the sandbox that no vault files are visible beside the workspace and that no Git repository covers it.

## Credentials

- **The sandbox holds placeholders.** `OPENAI_API_KEY` (and `KIMI_API_KEY` when enabled) contain a `sr-<provider>-…` placeholder. The `gej-machine` token reaches `gh` and Git as Docker Sandboxes' own `github` placeholder. Docker Sandboxes substitutes the real value only in requests to the provider's API host (`api.openai.com`, `api.kimi.com`) or GitHub's hosts.
- **The host resolves values on demand.** Docker Sandboxes stores a command, `<checkout>/bin/study-room resolve <name>`: an absolute path and a name, never a secret. It runs that command on the host and keeps the value only in its own memory. The resolver prints the value on stdout and nothing else.
- **OAuth state lives in Infisical, per host.** The provider's secret in the Agents project (`OPENAI_REFRESH_TOKEN`, per the captain's decision of 2026-10-06) holds one JSON document with an entry per installation ID. Each entry has the access token, refresh token, expiry, issued client and scopes. The keyring holds only the `sbx-host` handles (project ID, client ID, client secret).
- **`sbx-host` can write the Agents project.** Infisical's Free plan has no path-scoped grants, and the captain chose to keep the token in the existing project. The narrowing therefore happens in Study Room's client, which refuses to write anything but the configured OAuth secrets. It is not enforced by Infisical: anyone with the `sbx-host` client secret on this host could write other secrets in the Agents project. The client secret never enters the sandbox.
- **Refresh rotation is serialized.** A host-side lock is held across read, refresh and write. The entry is re-read under the lock, merged into the latest document, written back as one replacement, and read back twice to confirm before the lock is released. The second read is about a second and a half later, to catch another host's write landing just after this one. If another host's concurrent write dropped the entry, it is merged in again. A spent refresh token is never reused, and a lost write is reported with an instruction to re-authorize.
- **Nothing secret is printed.** Values are passed on stdin or in request bodies, never in arguments. Every error and log line goes through redaction, which removes registered values and token-shaped strings.
- **Authorization endpoints are host-only.** The sandbox's network policy allows the inference APIs, not `auth.openai.com` or `auth.kimi.com`. The sandbox never refreshes a token.

## Researcher policy

- The top-level session runs with `PI_SUBAGENT_ALLOWED=researcher`. The `study-room-guard` extension also rejects any other role, any spawn-time `model` not listed in `profiles.researcher.allowed_model_overrides`, any per-call thinking suffix, and any per-call `cwd`.
- The researcher definition is rendered from host configuration into a root-owned file. A spawn is refused if the definition the package would load differs from it, or if a project-local `.pi/agents/researcher.md` would shadow it.
- A resume is refused if the saved loadout (tools, model, thinking, spawn rights, cwd, config directory) differs from the trusted researcher loadout.
- The researcher has `web_search`, `web_fetch` and `safe_bash`, and no spawning tools.

These rules control which subagent profile launches. **They do not constrain what `safe_bash` runs.**

## `safe_bash` is not a security boundary

`safe_bash` blocks a short list of conspicuous patterns (`sudo`, `rm -rf /`, `mkfs`, `curl … | sh`, …). It is a blacklist around ordinary bash. The researcher can still:

- read, change and delete files in `Study Room/`, including with relative paths;
- run interpreters and network clients;
- in `web` mode, send study notes to any public HTTP(S) destination;
- see placeholder values (never the real substituted values);
- use the delegated GitHub authority of the `gej-machine` token through `gh` or Git.

The main Pi session has full bash. Docker Sandboxes keeps host files outside the mount and the real credentials out of reach. Obsidian Sync version history helps recovery; it does not prevent damage.

## Hardened `web_fetch`

- It accepts only `http` and `https` URLs on ports 80 and 443, without URL credentials.
- It rejects loopback, private, link-local, CGNAT, multicast, documentation, benchmarking, metadata and other special-use addresses (IPv4 and IPv6, including IPv4-mapped and NAT64 forms), and special-use or internal names (`localhost`, `.local`, `.internal`, `.home.arpa`, single-label names, …).
- It follows at most 5 redirects manually and re-checks every hop. It refuses HTTPS-to-HTTP redirects.
- It sends a fixed header set: no cookies, no authorization, nothing from the environment. Cookies a site sets are never replayed.
- It runs no JavaScript and keeps no browser profile. HTML is reduced to text by a tokenizer that drops scripts, styles, templates and comments. PDFs are parsed with pdf.js with eval disabled.
- Limits: 10 s to connect, 30 s for the whole operation, 5 MiB per response (decompressed), 60,000 characters of text, 30 PDF pages. Overflow text goes only to sandbox-ephemeral storage and is removed at session end. Writing under the vault mount is refused.
- Results are framed as untrusted third-party content, with the final URL as the source.

**DNS resolution.** Outside a sandbox, `web_fetch` resolves the host itself, rejects the hop if any answer is non-public, and connects to exactly the validated address, so DNS rebinding cannot slip in between check and connect. Inside Docker Sandboxes the sandbox has no DNS resolver: every request goes through the trusted proxy, which resolves and connects on the host. In that case `web_fetch` validates the URL and literal addresses, and the host-side network policy is the outer limit. In `balanced` mode only allowlisted domains are reachable. Docker Sandboxes does not apply its IP-range deny rules to host names, so on its own the proxy would let a public name that resolves to a private address through. The [host egress guard](#host-egress-guard) closes that: the host firewall rejects the daemon's connections to private, link-local and CGNAT addresses whatever name led there.

`web_fetch` is a safer default and a quality control, not an egress boundary: `safe_bash` can run `curl`.

## Network modes

| | `balanced` (default) | `web` |
| --- | --- | --- |
| Allowed | Docker's balanced baseline, plus provider APIs, GitHub, and `registry.npmjs.org` | the same, plus `**:443` and `**:80` |
| Denied (sandbox-scoped) | `localhost`, `*.localhost`, `host.docker.internal`, metadata names and addresses, loopback, private, link-local and CGNAT ranges, IPv6 loopback, ULA and link-local | the same |
| Scope | this sandbox only; global policy is untouched | this sandbox only; never a global allow-all |

The mode applies to the whole sandbox: the teacher, the researcher and every shell command get the same egress. Switching to `web` requires typed confirmation and shows the trade-off. The entry banner always shows the active mode.

## Host egress guard

Docker Sandboxes ends every sandbox's traffic in its host daemon's userspace network stack (gVisor's netstack). The daemon then opens the real connections itself. So the host firewall sees all sandbox egress as the daemon's own outbound traffic. There is no Docker bridge or sandbox subnet, which is why a `DOCKER-USER` rule would never see this traffic.

By the captain's decision of 2026-10-06 (option (a), backed by the host):

- **The daemon runs only inside a managed unit.** `study-room setup` installs `~/.config/systemd/user/study-room-sbx.service` (in `study-room.slice`), which runs `sbx daemon start` in the foreground.
- **The guard loads before the daemon starts.** The unit's `ExecStartPre` runs `sudo -n /usr/local/libexec/study-room/sbx-egress-guard load` from inside the unit's own cgroup. The guard refuses to load from anywhere else.
- **Rejected destinations.** The rule matches the unit's cgroup and its children. It rejects TCP with a reset, and other protocols with an ICMP "administratively prohibited":
  - IPv4: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16` (link-local and metadata) and `100.64.0.0/10` (CGNAT, which Tailscale uses);
  - IPv6: `fc00::/7` (unique local, including Tailscale's `fd7a:115c:a1e0::/48`) and `fe80::/10`.
- **Exceptions.**
  - Loopback stays open: the DNS stub, and host services a sandbox policy deliberately allows, such as the Magic Conch session listener on `127.0.0.1:8431`.
  - Port 53 stays open, because WSL2 points `resolv.conf` at a private address.
- **Scope.** The rule covers every Docker Sandbox this user runs, not only Study Room's; the captain accepted this. `tailscaled`, the Magic Conch hub (a Docker container), and the user's own programs live in other cgroups and are not matched. On WSL2 the rule lives in the Ubuntu distribution's own firewall, not in Windows.
- **The rule's form.** It uses `iptables-nft`'s cgroup match, so it lives in the nftables ruleset. nftables' native `socket cgroupv2` match needs `CONFIG_NFT_SOCKET`, which the current WSL2 kernel (6.6) does not build. The xtables cgroup match is built on WSL2 and on Ubuntu's kernels.
- **Reload on restart.** A cgroup match binds to the cgroup that exists when the rule loads, and a restarted service gets a new cgroup. The unit therefore reloads the guard at every start.
- **Fail closed.** If the guard cannot load, the daemon does not start. `study-room run` refuses to start unless the daemon runs inside the unit and the guard is loaded for the unit's current cgroup. `study-room doctor` reports the same checks.
- **Narrow sudo rule.** `/etc/sudoers.d/study-room-egress` permits only the guard's `load`, `unload` and `status` actions.

Residual risks:

- In `web` mode, a name that resolves to a loopback address could still reach a host service listening on port 80 or 443 on this machine. Loopback is deliberately left open; other devices on the network are not reachable.
- A Docker Sandboxes daemon started outside the unit is not covered. `study-room run` refuses to start Study Room while one is running, and `doctor` reports it.

## GitHub

The classic `gej-machine` PAT is used as a Docker-managed placeholder. Agents may clone, push branches and open pull requests. By operating policy they must not merge, push to protected or default branches, or change repository administration, security settings, secrets, collaborators or branch protection. Because a classic PAT and a full shell are available, this is policy rather than a technical boundary; a narrower token should replace the PAT when possible.

## What is excluded from Git

Sessions, OAuth state, receipts, caches, generated test artifacts, vault content and `node_modules` never enter this repository. A host test scans tracked files for credential-shaped values.
