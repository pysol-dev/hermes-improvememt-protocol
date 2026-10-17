# SSH authentication methods and decision flow

This is a comparison and a read-only planning surface, not permission to generate keys, install third-party apps, change PAM, reconfigure Tailscale SSH, enable multiplexing, or write server settings. The existing skill scripts implement only the `supported` rows; `keygen.sh` is a backwards-compatible name for *public-key registration*, not generation. This matrix separates identity storage, signing/approval, connection reuse, and network policy. Prompt cadence assumes a fresh SSH authentication unless otherwise noted; vendor settings and agent constraints must be verified rather than inferred.

| ID | Method | Sensitive material / authority | Typical fresh-auth prompt | Exportable identity? | Bound to one Mac? | Current skill scope |
| --- | --- | --- | --- | --- | --- | --- |
| M1 | Passphrase-protected Ed25519 file | Encrypted private file on disk | Passphrase each time **if no agent caches it** | Yes | No | Manual baseline; not generated/imported by scripts |
| M2 | OpenSSH agent (incl. KeePassXC integration) | Underlying key in file/vault; decrypted identity in agent memory | Loading once per agent/key lifetime; `ssh-add -c` can require confirmation per use | Yes, if the source is exportable | No | Supported KeePassXC public-key registration; agent controls stay manual |
| M3 | OpenSSH agent lock | M2 plus a **separate** lock passphrase | Once per unlock, not once per signature | Underlying key determines | No | Manual OpenSSH-agent control; not a Bitwarden-agent feature claim |
| M4 | macOS `--apple-use-keychain` / `UseKeychain` | Encrypted private file + passphrase in login Keychain | Keychain/unlock dependent; **not guaranteed per use** | Yes | No; setup is macOS-only | Supported Apple-Keychain backend for an existing encrypted Ed25519 file |
| M5 | Apple CTK nonexportable P-256, biometric | Mac Secure Enclave; on-disk OpenSSH FIDO handle is not the private key | Biometric on signing when correctly configured/verified | No | Yes | Mac-only research/verification required; no automatic generation |
| M6 | Apple CTK nonexportable P-256, no biometric | Same Secure Enclave | No configured per-signature biometric | No | Yes | Mac-only research/verification required; no automatic generation |
| M7 | Secretive Secure Enclave | Mac Secure Enclave via Secretive; agent signs | Per-signature Touch ID/Watch **only if configured and verified** | No | Yes | External app/security review and Mac test required |
| M8 | fssh retrofit of an existing key | Third-party Keychain-protected wrapping of exportable key (claims unverified) | Claimed per-connection biometric; **unverified** | Underlying key: yes | Not inherently nonexportable; migration must be assessed | Research-only; never install or migrate automatically |
| M9 | **Bitwarden** SSH agent | Encrypted Bitwarden vault; desktop agent signs | Configurable authorization on signing; verify two independent requests | **Yes**: SSH items are in JSON vault exports | No | Supported Ed25519 public-key registration; human GUI generation/import only |
| M10 | `ControlMaster`/`ControlPersist` | Connection-sharing modifier, not key auth | Reuses a previous connection, collapsing prompts | — | — | **Disabled** (`ControlMaster no`, `ControlPath none`) in managed connections |
| M11 | `pam_tid` with `pam_reattach` | Operation gate, not SSH signing | Per gated PAM operation | — | Requires macOS | Optional research; existing Swift LocalAuthentication helper is independent of PAM |
| M12 | Tailscale SSH `check` | Tailscale device/user identity + tailnet `ssh` policy | Identity-provider reauth at `checkPeriod` (default 12h; can be `always`) | No SSH key | No | Alternative transport, not configured by this skill; plain OpenSSH remains default |

“Mac-bound” means the signing *identity* cannot be used on another machine. M4's Keychain setup is Mac-specific but its encrypted private key is transferable. M9's vault item is not confined to one machine, and **may be exported**, so do not call it nonexportable or promise Touch ID for every signature on Linux. Unlocked agent memory and user-owned sockets are usable by same-user processes; no row makes arbitrary agent terminal commands a sandbox.

## Decision flow (before key registration)

1. Determine whether the **target path** is plain OpenSSH or the destination's Tailscale SSH listener. Network grants/ACLs govern either. If Tailscale SSH intercepts tailnet port 22, OpenSSH key auth is not used on that path; only then consider M12 and verify an explicit `ssh` policy with `action: check`. A tagged-source-to-tagged-destination SSH rule cannot use check mode. `tailscale status --json` alone is not proof of a remote node's effective `RunSSH`; independently inspect the destination/policy, and `ssh-check.sh` only accepts a connection when OpenSSH reports `publickey`.
2. Ask whether one key **must work on multiple machines**. If yes, do not recommend M5–M7 (nonexportable, Mac-bound). M9, M1/M2, or a portable encrypted file used with M4 are possible, with different tradeoffs.
3. Ask whether a **human must participate in each fresh authentication**. If yes, offer M9 with per-request desktop authorization, M1 without an agent, or, for one Mac and a *new* key, M5/M7 only after local verification. If no, M2 or M4 (Mac) are options; M6 is a Mac-only nonexportable option pending live test. `ssh-add -c` is a separate per-use confirmation for an OpenSSH agent; it is not biometric by itself.
4. Ask whether an **existing key must be retained**. M1/M2/M4 can keep it; Bitwarden can import one through its **human GUI** (which may briefly put private material on the clipboard outside Hermes). M8 claims biometric retrofit but is research-only; do not treat it as the unique migration route or claim it is audited. M5/M6/M7 require new enclave identities.
5. If prompts are too frequent, explain M10 as a separate **security tradeoff**, never automatically enable it. A ControlMaster child connection skips new SSH authentication and may bypass the expected Bitwarden/biometric prompt. Never use unbounded `ControlPersist yes` with a per-use gate. Mosh uses SSH for startup, then its own UDP session; reconnecting that UDP session is not a new SSH authentication.
6. Choose a compatible method explicitly. `scripts/auth-method-select.sh` is an advisory, secret-free JSON planner; it never configures auth. `--choose` selects one offered candidate. Until a Mac path is independently qualified, register only M2 (KeePassXC external agent), M4 (Apple Keychain existing encrypted file), or M9 (Bitwarden) with `key-register.sh --auth-method <id> --backend <matching backend>`.

Example read-only plan:

```sh
scripts/auth-method-select.sh --platform linux --multi-machine yes --human-per-use yes \
  --existing-key no --reduce-prompts no --tailnet-ssh no --choose M9
```

`--tailnet-ssh unknown` preserves uncertainty; never guess a transport. `required_config` in planner JSON is illustrative, **not** a free-form append operation: only `config-append.sh` writes validated Host blocks. The registry stores method/cadence/exportability metadata for implemented backends, not a verified hardware attestation. Existing JSONL rows remain readable; missing method fields are treated as legacy/unverified.

## Method-specific safety and verification notes

- M1: `ssh-keygen -t ed25519 -a 100 -f <private-path>` is a **human-run** setup example, not a skill command. For changing a passphrase, use interactive `ssh-keygen -p -f <private-path>`; **never** put `-N <passphrase>` or `-P <passphrase>` in process arguments or transcript. Encrypted file plus an already loaded agent behaves as M2, not M1.
- M2/M3: `ssh-add -t 3600 <path>` sets a lifetime; `ssh-add -c` asks for confirmation before each use; `ssh-add -x` / `ssh-add -X` lock/unlock an OpenSSH agent. Locking prompts once per unlock, not per signature. Keep private paths and passphrases out of model context. KeePassXC itself is an agent *client* loading into an external OpenSSH agent.
- M4: `ssh-add --apple-use-keychain <private-path>` explicitly opts into Apple's passphrase storage. Bare `-K` is ambiguous across platform/version/resident-key workflows; never emit it for Keychain. `UseKeychain yes` is Apple-specific; avoid a global `Host *` mutation and do not promise per-use biometrics.
- M5/M6: A third-party technical write-up describes Tahoe-era `/usr/lib/ssh-keychain.dylib` as a `SecurityKeyProvider` and `sc_auth create-ctk-identity -k p-256-ne -t bio|none`, with an OpenSSH `sk-ecdsa-sha2-nistp256@openssh.com` credential handle. This is **not established as a supported automatic workflow on our Linux host**. On a Mac verify OS version, `man sc_auth`, provider existence/feature support, current working-directory/output collision behavior, server acceptance (OpenSSH FIDO support appeared in 8.2), Touch ID in the actual launch context, and recovery key/alternate admin access *before* any key creation. A credential handle still deserves protection; never expose its file bytes to a tool result. Avoid blindly changing `sshd_config` or using an unattended askpass/PIN bypass recipe.
- M7: Secretive states that nonexportable enclave keys cannot be backed up or migrated. Check its current app/agent instructions and signing prompts locally; do not infer an arbitrary socket path or install an unreviewed binary as part of this skill.
- M8: The source supplied for fssh is a secondary article, not an audited upstream release or verified secure migration procedure. No runnable commands are provided here. An existing key could instead stay encrypted on disk, use Keychain (Mac), or be imported into Bitwarden by the human.
- M9: Bitwarden's official export documentation says SSH keys are included in JSON vault exports (including encrypted JSON), so vault storage is **not hardware nonexportability**. Its authorization cadence is configurable; the human verifies it with two fresh requests. Do not ask Hermes to dump a vault export or private item. Only list public keys/fingerprints via the agent.
- M10: A bounded `ControlPersist` needs a private socket directory and an explicit expiry, but this skill's `ssh-check` / `ssh-exec` must not silently reuse a master. Even a correct `%C` ControlPath and `ControlMaster=no` on a command is insufficient if `ControlPath` still refers to an existing master; the skill forces `ControlPath none`. A future `control-master.sh` requires separate review, explicit opt-in, and prompt-collapse tests.
- M11: `pam_reattach` may help Touch ID *sudo PAM* in tmux; it is **not mandatory** for the existing direct Swift `LocalAuthentication` helper. Never copy/uncomment `/etc/pam.d/sudo_local` as an incidental side effect of SSH selection. Verify the chosen gate from the actual Hermes/tmux launch context on a physical Mac.
- M12: Tailscale's `ssh` policy `action: check` + `checkPeriod` layers on top of an allowed **network** access grant/ACL. Plain OpenSSH over Tailscale still uses network grants/ACLs and SSH keys. Tailscale SSH intercepts tailnet port 22 and uses SSH auth type `none` on that path; connections on other interfaces continue through the ordinary OpenSSH daemon and its normal key-login rules.

## Future contracts (NOT implemented)

- `enclave-keygen.sh`: only after Mac/CTK provider feature detection, collision-safe output handling, prompt testing and a non-leaking public-result boundary. This must never run `ssh-keygen -K` from an arbitrary current directory or expose a handle/private file to model output.
- `agent-wire.sh`: only after the existing validating config writer explicitly supports reviewed provider/agent options and rejects executable or indirection directives. It must not free-form edit `~/.ssh/config`.
- `control-master.sh`: only after an explicit bounded-persistence policy and regression tests proving both prompt collapse and teardown. Skill-managed connections remain un-multiplexed by default.

## Sources and confidence

- OpenSSH `ssh-add` (agent lifetimes, lock, confirmation): https://man.openbsd.org/ssh-add ; `ssh_config`: https://man.openbsd.org/ssh_config
- Bitwarden SSH item, import and agent: https://bitwarden.com/help/about-ssh/ ; https://bitwarden.com/help/ssh-agent/ ; export: https://bitwarden.com/help/export-your-data/
- Tailscale SSH interception, policy `check`/`checkPeriod` and tagged-source restriction: https://tailscale.com/docs/features/tailscale-ssh
- Secretive upstream README (Secure Enclave portability and access): https://raw.githubusercontent.com/maxgoedjen/secretive/main/README.md
- Apple Keychain guide: https://support.apple.com/guide/terminal/use-keychain-to-store-ssh-passphrases-trml5c1d7234/mac
- CTK exploration (community, **not** first-party compatibility promise): https://gist.github.com/arianvp/5f59f1783e3eaf1a2d4cd8e952bb4acf
- fssh claim (secondary source, **not verified**): https://korben.info/en/protect-ssh-keys-touch-id-macos.html
