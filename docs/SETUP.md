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

When a change only takes effect in a new session (group membership, a new keyring daemon), setup says so and stops. Log out and back in, then run `study-room setup` again. Finished steps are not repeated: a second run on a ready host reports "No host changes are needed."

`--yes` approves the host changes. It never skips a sign-in ceremony.

## 4. The ceremonies

After the host changes, setup walks through the interactive steps:

1. **Docker sign-in**: `sbx login`.
2. **Infisical handles**: paste the project ID, the `sbx-host` client ID, and the client secret for this machine. Input is hidden and goes straight into the Secret Service under the `study-room` namespace; it is never written to a file. Optionally give a separate project ID for Study Room's OAuth state (see below). Setup then checks it can read the `gej-machine` token and prints only its length and shape.
3. **Obsidian**: see [step 6](#6-obsidian-sync-onboarding).
4. **OpenAI**: `study-room auth openai` opens "Sign in with ChatGPT" in your browser. The resulting authorization (access token, refresh token, expiry, issued client) is stored in Infisical at `/study-room/oauth/openai/<installation-id>`, for this host only.

## 5. Infisical access

Study Room reads the existing `GITHUB_GEJ_MACHINE_PAT` secret and writes provider OAuth state only under `/study-room/oauth/`. An Infisical administrator must:

1. create the folder `/study-room/oauth` in the `dev` environment (Infisical checks folder-creation rights on the parent, so the identity cannot create the top folder itself);
2. give `sbx-host` read and write access to `/study-room/oauth/**` and nothing broader.

Infisical offers path-scoped access through additional privileges (Pro plan) or custom roles (higher tiers). On the Free plan only whole-project roles exist. In that case keep the OAuth state in a separate project that `sbx-host` may write, and enter its ID at the optional prompt. Which option to use is an open decision: see [Live acceptance](ACCEPTANCE.md#gates).

Check the result with:

```bash
study-room verify --live infisical
```

It writes and deletes a probe inside the Study Room path, and confirms that a write outside it is refused.

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
