# Contributing

1. Fork and create a feature branch from `main`.
2. `make vet test` must pass; run `golangci-lint run` if installed.
3. Keep the safety invariants in [docs/PLAN.md](docs/PLAN.md): never flush the ruleset, never touch foreign tables, never block protected ports.
4. Add an entry under a new version heading in `CHANGELOG.md` for user-visible changes.

## Releasing
Add a `## [X.Y.Z] - YYYY-MM-DD` section at the top of `CHANGELOG.md` and merge to `main`;
the release workflow tags `vX.Y.Z` and publishes binaries automatically.
