# Setup runbook

From a supported host with nothing preinstalled (no Pi, no Obsidian) to a first lesson. Every host change is shown before it happens and needs your approval; sign-in steps always stay interactive.

## 1. Supported hosts

| | Native Ubuntu | WSL2 |
| --- | --- | --- |
| OS | Ubuntu Desktop 24.04 LTS, x86_64 | Ubuntu 24.04 distribution on Windows 11, x86_64 |
| Desktop | a local Wayland or X11 session | WSLg |
| systemd | yes (default) | `[boot] systemd=true` in `/etc/wsl.conf`, then `wsl --shutdown` from Windows |
| KVM | virtualization enabled in firmware | nested virtualization enabled for WSL2 |
| Also | sudo, a Secret Service keyring, outbound network | sudo inside the distribution, outbound network |

Not supported: ARM hosts, headless Ubuntu Server, and provisioning WSL or Windows itself (enable WSL, install the distribution and turn on systemd and nested virtualization yourself first).

You also need:

- the existing Infisical project and the `sbx-host` machine identity, with one client secret created for this machine (Infisical website → `sbx-host` → Universal Auth → create client secret). See [Infisical access](#5-infisical-access) for the permission the identity needs;
- a Docker account for Docker Sandboxes;
- an Obsidian account with Sync and the existing remote vault;
- an OpenAI ChatGPT subscription for the initial provider path.

## 2. Get the trusted checkout

```bash
git clone https://github.com/digigrant/study-room.git ~/study-room
```

This checkout is trusted host code. It is never mounted into the sandbox. Keep it outside the vault.

## 3. Run setup

```bash
~/study-room/bin/study-room setup
```

Setup first prints what it found and the exact commands it proposes, for example:

```text
Proposed host changes (nothing has been changed yet):
[packages] Install libsecret-tools, gnome-keyring, dbus-user-session, xdg-utils, gnupg
    $ sudo apt-get update
    $ sudo apt-get install -y --no-install-recommends libsecret-tools ...
[docker-repo] Add Docker's apt repository (key fingerprint verified against the lock)
[docker] Install docker-ce, docker-ce-cli, containerd.io, docker-buildx-plugin, docker-sbx=0.46.0-...
[kvm-group] Add <you> to the kvm group
[docker-group] Add <you> to the docker group (optional)
[obsidian] Install Obsidian Desktop 1.14.4 (.deb, sha256 85b10dcba6edfc1c…)
```

It then asks before each change. What each change is for:

- **packages**: `secret-tool` and a Secret Service (gnome-keyring) for the Infisical handles, a D-Bus user session, `xdg-utils` to open the browser, and `gnupg` to verify Docker's repository key.
- **docker-repo / docker**: Docker's apt repository, with its signing-key fingerprint checked against the lock. Docker Engine builds the sandbox image; `docker-sbx` is Docker Sandboxes, installed at exactly the pinned version. If the repository does not offer that version, setup stops; it never installs a newer one instead.
- **kvm-group**: Docker Sandboxes runs each sandbox as a KVM microVM.
- **docker-group** (optional): lets `study-room build` use Docker without sudo. Membership is root-equivalent on the host. If you decline, use `study-room run --sudo-docker`.
- **sbx-policy**: only if Docker Sandboxes' global network policy was never initialized, `sbx policy init balanced`. An existing policy is never changed. All of Study Room's own rules are scoped to its sandbox.
- **obsidian**: the pinned `.deb`, downloaded to `~/.cache/study-room/downloads` and checked against the lock's SHA-256 before `sudo apt-get install`.
- **egress-guard** (required, on native Ubuntu and on WSL2): runs the Docker Sandboxes daemon in a managed unit, with a host firewall rule that stops every sandbox from reaching other devices on your network. See [the host egress guard](#host-egress-guard).

When a change only takes effect in a new session (group membership, a new keyring daemon), setup says so and stops. Log out and back in, then run `study-room setup` again. Finished steps are not repeated: a second run on a ready host reports "No host changes are needed."

`--yes` approves the host changes. It never skips a sign-in ceremony.

### Host egress guard

Docker Sandboxes makes every sandbox connection from its host daemon. Its own policy does not check what a host name resolves to. Without a host rule, a public name pointing at a home-network address (your router, a NAS, a phone on Tailscale) could therefore be reached from a sandbox in `web` mode. The guard prevents that. Setup's `egress-guard` change:

1. installs the guard as root at `/usr/local/libexec/study-room/sbx-egress-guard`;
2. installs a sudo rule, `/etc/sudoers.d/study-room-egress`, checked with `visudo -cf`, that allows only the guard's `load`, `unload` and `status` actions;
3. writes the user units `~/.config/systemd/user/study-room.slice` and `study-room-sbx.service`;
4. stops any Docker Sandboxes daemon started another way;
5. runs `systemctl --user enable --now study-room-sbx.service`.

At every start the unit loads the guard from inside its own cgroup, then runs `sbx daemon start`. The guard rejects the daemon's connections to `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, `100.64.0.0/10`, `fc00::/7` and `fe80::/10`. It allows loopback and port 53.

- **On WSL2** the rule lives in the Ubuntu distribution's own firewall (iptables-nft inside WSL), not in Windows Defender Firewall. Nothing changes on the Windows side. Reach home-network devices from Windows as usual.
- **Every sandbox is covered**, including devenv's. Tailscale and the Magic Conch hub run outside the unit and are not affected; the live check proves it.
- **Never start the daemon any other way** (`sbx daemon start -d` from a shell, for example). `study-room run` refuses to start while a daemon runs outside the unit, and `study-room doctor` reports it. To fix it:

  ```bash
  sbx daemon stop
  systemctl --user restart study-room-sbx.service
  ```

- If the guard cannot load, for example because the kernel lacks the xtables cgroup match, the daemon does not start, and `journalctl --user -u study-room-sbx.service` shows why.

Prove it on the real host (it asks for confirmation and `sudo`):

```bash
study-room verify --live egress --tailscale-peer <tailscale-ip>:<port>
```

The check:

- creates a dummy interface with `10.213.0.1` and a test web server;
- confirms the host can reach it, but the sandbox cannot, by address or through `10-213-0-1.sslip.io`, even with a temporary sandbox allow rule;
- confirms the sandbox still reaches `api.github.com`;
- shows that `tailscaled` and the Magic Conch hub run outside the daemon's unit, and that Tailscale and the hub's session port keep working;
- with `--tailscale-peer`, connects to that peer from the host and fails to reach it from the sandbox.

Everything temporary is removed afterwards.

## 4. The ceremonies

After the host changes, setup walks through the interactive steps:

1. **Docker sign-in**: `sbx login`.
2. **Infisical handles**: paste the project ID, the `sbx-host` client ID, and the client secret for this machine. Input is hidden and goes straight into the Secret Service under the `study-room` namespace; it is never written to a file. Setup then checks it can read the `gej-machine` token and prints only its length and shape.
3. **Obsidian**: see [step 6](#6-obsidian-sync-onboarding).
4. **OpenAI**: `study-room auth openai` opens "Sign in with ChatGPT" in your browser. The resulting authorization (access token, refresh token, expiry, issued client) is stored in the `OPENAI_REFRESH_TOKEN` secret of the Agents Infisical project, as this host's entry (keyed by its installation ID). If that secret holds a value Study Room did not write, `auth` asks before replacing it.

## 5. Infisical access

Study Room uses the existing Agents project and the `sbx-host` identity:

- it reads `GITHUB_GEJ_MACHINE_PAT` (environment `dev`, path `/`);
- it reads and writes `OPENAI_REFRESH_TOKEN` (same environment and path), which the captain created for this purpose;
- it reads and writes `KIMI_REFRESH_TOKEN` only once Kimi is enabled (created on first `study-room auth kimi` if it does not exist).

`sbx-host` therefore needs write access in the Agents project. The captain decided on 2026-10-06 to keep the token there rather than buy path-scoped permissions or create another project. Study Room's own client refuses to write any secret other than the OAuth secrets named in its configuration (`infisical.oauth_secrets`).

Several hosts can share the secret. Its value is a JSON document with one entry per installation ID. Each host rotates only its own entry, so WSL2 and native Ubuntu never spend each other's refresh tokens.

Check access with:

```bash
study-room verify --live infisical
```

It reads the GitHub token (showing only its length) and the OAuth secret, and writes the OAuth secret's current value back unchanged to prove write access.

## 6. Obsidian Sync onboarding

```bash
study-room obsidian setup
```

1. Study Room creates an empty folder for a **fresh Linux replica**, by default `~/.local/share/study-room/obsidian-vault` (change `vault.path` with `study-room config set`). Never point it at the Windows vault; Windows Obsidian keeps its own replica.
2. In Obsidian choose **Open folder as vault** and select that folder.
3. **Settings → Core plugins → Sync**, sign in, choose the existing remote vault, enter its encryption password, and wait until it is fully synced.
4. Make sure the vault has a `Study Room` folder. Study Room offers to create it if it is missing.

Study Room never sees your Obsidian account, Sync login or encryption password. The vault must not be a Git repository.

## 7. Choose models

```bash
study-room models openai
study-room config set profiles.main.model <id>
```

`main.thinking` defaults to `max`. If the model you choose does not support `max`, entry stops until you accept a fallback explicitly, for example `study-room config set profiles.main.thinking_fallback xhigh`. The researcher follows the main provider and model until you set `profiles.researcher.model`; its thinking defaults to `medium`. An optional dedicated search model goes in `profiles.search.model`.

## 8. First run

```bash
study-room run
```

`run` checks readiness, starts or reuses Obsidian, builds the sandbox image from the lock (the first time only), registers sandbox-scoped placeholder secrets, creates the sandbox with only `Study Room/` mounted, applies the network mode, and attaches to the tmux session with Pi. The banner shows the platform, the network mode, the models with requested and effective thinking levels, Obsidian readiness, drift and verification warnings, and the `md-log` rule.

### Lesson logs

1. Create a new, empty note for the lesson log.
2. Run `/md-log <path>` in Pi.
3. While logging is active, view that note in Obsidian but do not edit it.
4. Run `/md-unlog` (or end the session) before you edit it.

### Optional: live checks

```bash
study-room verify --live provider research github obsidian
```

Each check shows the exact model, thinking level, request and output limits, search use and timeout, and runs only after you type `yes`. The verification model must first be pinned after you inspect the catalog: `study-room bump verification-model openai <id>` on a branch.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| `keyring locked` from Docker Sandboxes' secret refresh | Run `study-room run` or `study-room doctor` in the desktop session; they open the unlock prompt. |
| `Infisical rejected the sbx-host login (401)` | Check the client secret. Three failed logins lock the identity for about 5 minutes. |
| `authorization expired or revoked` | `study-room auth openai`. |
| `pin/checksum mismatch` during a build | A download or upstream no longer matches the lock. Nothing was installed; investigate before any `study-room bump`. |
| A blocked fetch in `balanced` mode | Expected outside the allowed destinations; use `study-room network web` (with its risk) if the lesson needs it. |
| `the host egress guard is not protecting the Docker Sandboxes daemon` | `sbx daemon stop; systemctl --user restart study-room-sbx.service`. If the unit fails, read `journalctl --user -u study-room-sbx.service`. |
