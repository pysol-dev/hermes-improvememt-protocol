# ssh-key-lifecycle

Hermes / Agent Skills-compatible public-key inventory and OpenSSH operations. This is the versioned source of `SKILL.md` and its scripts. Bitwarden is the default SSH agent backend; KeePassXC (an agent client using OpenSSH's agent) and macOS Keychain (passphrase for an encrypted local key) are opt-in. It never reads a vault item into model context.

## Install into Hermes

From a trusted clone, link this directory into the active profile's skills directory:

```sh
mkdir -p "$HOME/.hermes/skills/security"
ln -s /absolute/path/to/hermes-improvememt-protocol/ssh-key-lifecycle "$HOME/.hermes/skills/security/ssh-key-lifecycle"
```

The installed path must be free first. Do not replace a customized skill without preserving it. Load it in a new Hermes session or use `/reload-skills` for slash-command discovery. For another agentskills.io client, link the same directory into its skill path; its code and metadata do not rely on Hermes runtime APIs.

## Commands

Run from the component directory:

```sh
scripts/key-search.sh --doctor --backend bitwarden
scripts/auth-method-select.sh --platform linux --multi-machine yes --human-per-use yes --existing-key no --reduce-prompts no --tailnet-ssh no --choose M9
scripts/key-register.sh client app host --backend bitwarden --auth-method M9 --public-file /home/you/.ssh/id_ed25519_client_app_host.pub --vault-ref item-id
scripts/config-append.sh alias host.tailnet.example id_ed25519_client_app_host
scripts/ssh-check.sh alias
scripts/ssh-exec.sh alias -- hostname
scripts/ssh-exec.sh alias -- printf '%s' 'a safe public argument'
```

`key-register.sh` accepts an existing public key offered by the selected agent; it does not generate a private key. The older `keygen.sh` remains a compatibility alias. SSH host keys must be independently verified and already trusted (`StrictHostKeyChecking=yes`). `ssh-exec.sh` requires two local approvals: a connection preflight and an exact-command approval. It returns only status and a command digest; remote stdout/stderr is discarded. Arguments are shell-quoted and bounded; obvious credential-looking arguments are rejected, but this check is heuristic, not a secret detector. Never embed credentials in SSH argv or the remote command. The command runs under the remote account's normal shell; approve it only when the displayed command and target match your intent.

Choose an auth method **before** registration with `auth-method-select.sh`. Its M1–M12 matrix covers encrypted disk keys, OpenSSH agent/lock, Apple Keychain, Mac Secure Enclave CTK, Secretive, fssh (research-only), Bitwarden, multiplexing, a separate macOS approval gate, and Tailscale SSH check mode. The selector is read-only: it never generates a key or edits a Host block, and future/nonportable methods are explicitly labeled. Only M2 (KeePassXC), M4 (Apple Keychain), and M9 (Bitwarden) are registered by this version. Bitwarden's JSON vault export **includes SSH key items**; it is not a nonexportable hardware vault. ControlMaster remains disabled in managed SSH even when the planner mentions it as a prompt-frequency tradeoff. See `references/auth-methods.md` for corrections and source links.

On Linux Snap, install the official Bitwarden desktop app (`sudo snap install bitwarden --channel=latest/stable`), connect its `password-manager-service` interface, and sign in personally. In Settings enable its SSH Agent and ask for authorization on every use. The documented socket is `~/snap/bitwarden/current/.bitwarden-ssh-agent.sock`; set `SSH_AUTH_SOCK` to that absolute path in the trusted session launching Hermes before using this skill. `key-search.sh --doctor` distinguishes an installed desktop executable from the optional `bw` CLI and will report the socket as unavailable until the agent has actually started. Do not put login credentials into a terminal or transcript. See the backend reference for native Linux, Flatpak, and macOS socket variants.

macOS uses a Swift LocalAuthentication helper for Touch ID on these skill operations; Linux uses Zenity for human GUI approval. Both deny if no interactive UI is available. The vendor's SSH signing prompt is a separate setting; verify per-request approval in the vault application. Nothing configures Tailscale ACLs or changes the remote host by default. `rotate.sh` and `ts-bootstrap.sh` are read-only plans until a tested secret-safe bootstrap and rollback exists.

## Development and limits

```sh
python3 -m unittest discover -s scripts -p 'test_*.py' -v
for f in scripts/*.sh; do bash -n "$f"; done
```

CI runs the unit suite on Linux and macOS and typechecks the Swift approval helper on macOS. The tests mock GUI/vault/network boundaries; a passing test is not evidence of a live Touch ID prompt, a vault signature, or a provisioned tailnet device. The local Hermes `skills_guard` currently rates this SSH-specific source as caution from static-pattern matches; review findings before installing it through a community skill hub. See `references/security-and-setup.md` for backend differences and sources.
