# PortSentinel — Implementation Plan

## Phase 1 — MVP (this iteration)

| Area | Package | Status |
|------|---------|--------|
| YAML config, validation, modes (audit/dry-run/enforce/monitor) | `internal/config` | done |
| Concurrent TCP connect probe (IPv4/IPv6), banner grab | `internal/probe` | done |
| Local listening sockets from `/proc/net/{tcp,tcp6}` + PID/process mapping | `internal/inventory` | done |
| Allowlist, ranges, protected SSH port, expiring exceptions | `internal/policy` | done |
| Firewall interface + nftables adapter (dedicated `inet portsentinel` table) | `internal/firewall` | done |
| Plan / apply / snapshot / rollback, timed confirm-or-revert | `internal/remediation` | done |
| JSON Lines audit log | `internal/audit` | done |
| Terminal table + JSON reports | `internal/report` | done |
| Interactive TUI (Bubble Tea) | `internal/tui` | done |
| CLI: init, scan, audit, plan, apply, rollback, rules, verify, doctor, tui | `cmd/portsentinel` | done |

## Phase 2 — Safe automation
- External verifier endpoint (`portsentinel verify --remote`) running on a second host.
- Active SSH session detection (`SSH_CONNECTION`) added to protected set automatically. *(done: basic)*
- IPv6-specific rule sets, source-CIDR allow rules.
- Drift detection: compare live `nft list table` with persisted state.

## Phase 3 — Production hardening
- UDP probes (DNS, NTP, SNMP payloads).
- Docker published-port discovery (`DOCKER-USER` chain interaction).
- systemd unit + timer (`deploy/`), Prometheus metrics, notifications.
- Network-namespace integration tests (`ip netns`), root-only build tag `nsintegration`.

## Phase 4 — Advanced
- Multi-server management, dashboard, cloud firewall adapters, policy templates.

## Safety invariants
1. PortSentinel only touches the `inet portsentinel` nftables table; it never flushes the ruleset.
2. Every apply snapshots the previous managed table to `state_dir` before changing anything.
3. Rule scripts are validated with `nft -c -f` before being applied atomically with `nft -f`.
4. Protected ports (SSH + `management_ports` + the port of the current SSH session) are never blocked.
5. `apply` with `rollback_timeout` reverts automatically unless confirmed.
