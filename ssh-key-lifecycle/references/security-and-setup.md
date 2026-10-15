# SSH backends and execution model

## Provider matrix

| Backend | Where private key lives | Agent signs? | Creation path | Approval behavior |
| --- | --- | --- | --- | --- |
| Bitwarden (default) | Encrypted Bitwarden vault, not a local private-key file | Bitwarden desktop SSH agent | Generate Ed25519 SSH Key item in Bitwarden desktop/web UI | Desktop has `Ask for authorization when using SSH agent` setting; choose per-use authorization and verify twice. Bitwarden unlock/biometric alone does not assert every signature is biometric. |
| KeePassXC | Database attachment or existing encrypted private file; loaded into separate OpenSSH agent | OpenSSH agent holds loaded identity | Manually import existing Ed25519 key in GUI; no secret CLI dump | KeePassXC does not itself provide an SSH agent. Use OpenSSH confirmation constraints if supported; per-use biometrics not built in. |
| Apple Keychain (macOS) | Passphrase in Keychain; encrypted private file remains on disk | macOS/OpenSSH agent | Existing encrypted Ed25519 key, human-managed | LocalAuthentication Swift helper prompts Touch ID for this skill's operations. Apple's agent need not prompt per signature; never conflate Keychain with nonexportable Secure Enclave. |

Bitwarden desktop agent socket shown in its own docs: on Linux `~/.bitwarden-ssh-agent.sock`; on macOS `~/Library/Containers/com.bitwarden.desktop/Data/.bitwarden-ssh-agent.sock` (some builds also use `~/.bitwarden-ssh-agent.sock`). Set `SSH_AUTH_SOCK` to the real socket and verify with `ssh-add -L` locally; the script only accepts those Bitwarden locations. KeePassXC uses the running system `ssh-agent`, so its socket is discovered from `SSH_AUTH_SOCK`; script checks socket ownership but cannot attest that KeePassXC loaded each key. macOS Keychain uses current macOS `SSH_AUTH_SOCK`. All three require Ed25519 and a corresponding public key on disk. Do not install all three at once just to pass doctor.

Public key export: `~/.ssh/id_ed25519_<client>_<app>_<host>.pub` mode 0600, standard single-line `ssh-ed25519` SSH wire format. Use a nonsecret opaque item handle for `--vault-ref`; this is metadata, not a token or vault URI containing credentials. Registry is append-only JSONL for software operations, but same-user edits could alter it. The audit records timestamps, fingerprints, initiating-profile *claim*, and approval method; it is not sealed evidence.

## Approval

Registration, config append, and SSH connectivity checks call an OS UI process and deny without UI success: macOS executes `swift scripts/biometric-approve.swift` with `LAContext.deviceOwnerAuthenticationWithBiometrics`, explicitly no device-password fallback; Linux executes `zenity --question` (human confirmation, **not** biometric). Both have a 600-second outer timeout. This is a genuine external UI action but not a hard policy against a process that may edit/skip scripts. For higher assurance, restrict raw tool access and use a separately permissioned broker. A standard Hermes terminal with a cooperative agent is fine for day-to-day operations; the same-user caveat is scoped to an *adversarial model* threat, not a claim that SSH cannot work.

GUI approval does not automatically prove Bitwarden itself asks on every signing request; test two separate SSH operations. Config binds `IdentityAgent` to the Bitwarden socket or `SSH_AUTH_SOCK`, `IdentitiesOnly yes`, disables password fallback and connection multiplex reuse. Vault agents use the public-key `IdentityFile`; the Apple Keychain backend uses the local encrypted private file with `UseKeychain yes` and `AddKeysToAgent yes`. On a Mac a human can generate a passphrase-protected Ed25519 file in a private terminal and load it with Apple's `ssh-add --apple-use-keychain <private-path>`; never capture that terminal's private material or passphrase in Hermes. A Mac biometric prompt from a noninteractive/tmux gateway is not proven until exercised on that Mac. Secretive is a separate Secure Enclave app with EC keys; not a native Keychain Ed25519 backend and not silently substituted.

## Out-of-scope operations

`key-register.sh` (`keygen.sh` compatibility alias) registers an existing key; it does not generate private bytes. CLI generation inside either vault is not documented and must not be improvised with `bw get item` or `keepassxc-cli show` (both can emit secrets) or `ssh-keygen -N "$(secret command)"` (argv leakage). KeePassXC's normal creation/import flow may involve a temporary private file that must be handled by the human outside Hermes; that flow does not satisfy a strict never-written-to-disk requirement. Bitwarden is preferred for v1.

`ssh-exec.sh` is a separately approved generic remote command path with a publickey preflight, no SSH connection sharing, quoted POSIX-shell argv and status-only tool results. It writes approval, success/failure, and command SHA-256 metadata to the local audit journal; the digest is not proof that the intended state changed. It never returns remote stdout/stderr, so use a separate approved predicate (a command whose exit status proves the intended state) for verification. Credential-looking argv is blocked heuristically, not exhaustively. Tailscale SSH could theoretically be enabled on the target between preflight and execution; the script still rejects a non-publickey auth method after the command, but it cannot undo a command that already ran on that raced connection. For hard enforcement, pin/control server-side transport and policy. `ts-bootstrap.sh` and `rotate.sh` remain plans because neither a nonleaking tagged Tailscale auth-key transport nor safe remote revocation/rollback is implemented. A one-off auth key's expiration differs from device node-key expiration, and `tailscale up --auth-key=$TOKEN` exposes token in argv. The tailnet grants/ACL network filter works for both plain OpenSSH and Tailscale SSH; Tailscale SSH interception on target port 22 removes ordinary key authentication on that path. The SSH check refuses any authentication method other than publickey. The optional third-party SSH MCP was not installed or trusted.

## Static scan and known limitations

This locally authored skill loads, validates its frontmatter and passes the included unit tests, but the local `skills_guard` static scan reports warnings on SSH-related code and prose. Do not report a passing guard or force community installation until findings are reviewed. No backend or GUI is installed in the current Linux host, so only mock-gated integration paths and CLI fail-closed behavior have been exercised. macOS Swift has not been compiled/tested on a Mac. No live host access files, tailnet policy, or SSH server settings were touched.

## Sources

- Bitwarden SSH Agent: https://bitwarden.com/help/ssh-agent/
- Bitwarden key item types and fallback warning: https://bitwarden.com/help/about-ssh/
- KeePassXC SSH Agent integration: https://raw.githubusercontent.com/keepassxreboot/keepassxc/develop/docs/topics/SSHAgent.adoc
- Apple Terminal Keychain guide: https://support.apple.com/guide/terminal/use-keychain-to-store-ssh-passphrases-trml5c1d7234/mac
- Secretive Secure Enclave caveats: https://github.com/maxgoedjen/secretive ; https://raw.githubusercontent.com/maxgoedjen/secretive/main/FAQ.md
- OpenSSH agent and config: https://man.openbsd.org/ssh-add ; https://man.openbsd.org/ssh_config
- Tailscale ACL/grants: https://tailscale.com/docs/features/access-control/acls ; Tailscale SSH: https://tailscale.com/docs/features/tailscale-ssh
