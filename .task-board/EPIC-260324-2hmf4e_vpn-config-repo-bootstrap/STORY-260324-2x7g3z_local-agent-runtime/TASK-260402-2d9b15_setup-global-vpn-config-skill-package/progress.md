## Status
development

## Assigned To
codex

## Created
2026-04-02T14:24:15Z

## Last Update
2026-04-02T14:59:43Z

## Blocked By
- (none)

## Blocks
- TASK-260402-qiah94

## Checklist
- [x] Inventory required CLI/system tools for vless-tun, openconnect-tun, vpn-auth, CSD, and TOTP auth flows
- [ ] Detect missing prerequisites locally and install them through the supported setup path
- [x] Install the vpn-config skill into the global runtime and fan out repo-local symlinks from that global install
- [ ] Remove stale resource copies and degitize leftover skill artifacts so only the working global runtime scheme remains

## Notes
This task covers global vpn-config skill packaging/setup, prerequisite verification, missing tool installation, TOTP-related auth prerequisites, global install, repo-local symlink fan-out, and cleanup of stale degitized/resource leftovers.
This task also needs to support the new agent-facing setup flows: when the agent says it can run openconnect-tun setup or vless-tun setup, the global vpn-config skill/runtime must already have the required toolchain, TOTP/auth prerequisites, and global install/symlink layout in place for those commands to work end-to-end.
Updated scripts/setup.sh to verify/install stable prerequisites (ripgrep, pipx, openconnect, oath-toolkit, python3, vpn-slice), keep vpn-auth as an explicit prerequisite warning because its install source is still unresolved, install the vpn-config skill into the global runtime, and fan out repo-local symlinks from that global install instead of pointing local shims directly at the repo skill directory.
Added scripts/deinit.sh as the paired uninstall path for multi-tun. It removes managed global/local skill links and ~/.local/bin symlinks by default, and only purges config/cache/keychain/build artifacts behind explicit --purge-* flags.

## Precondition Resources
(none)

## Outcome Resources
(none)
