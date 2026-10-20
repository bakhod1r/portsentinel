# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-10-20

First MVP preview.

### Added
- Concurrent TCP connect scanner (IPv4/IPv6, hostname resolution, banner grab); no Nmap needed.
- Local listener inventory from `/proc/net/tcp{,6}` with PID/process mapping.
- Default-deny policy: allowlist, port ranges, expiring exceptions, protected SSH/management ports
  and the port of the current SSH session.
- nftables backend confined to a dedicated `inet portsentinel` table, validated with `nft -c` and applied atomically.
- Plan/apply with snapshot, post-apply verification, timed confirm-or-revert, crash recovery and `rollback`.
- JSON Lines audit log.
- CLI: `init`, `scan`, `audit`, `plan`, `apply`, `verify`, `rules`, `rollback`, `status`, `monitor`, `doctor`, `tui`, `version`.
- Interactive Bubble Tea TUI (Findings / Plan / Rules).
- systemd service and timer units.

### Known issues
- `apply` verifies from the same host; that traffic arrives over `lo`, which the managed chain accepts,
  so verification fails and the change is reverted. Use `audit`, `plan` and `tui` for now.
- UFW/iptables adapters, UDP probing, Docker port discovery and network-namespace tests are not implemented yet.
