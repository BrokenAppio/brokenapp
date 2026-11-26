# BrokenApp Documentation

BrokenApp is a single zero-dependency Rust binary that builds a write-guarded behavioral map and multi-role diff of any local web application over Chrome DevTools Protocol (CDP).

## Guides

| Document | Covers |
|---|---|
| [`ui-map.md`](ui-map.md) | `.brokenapp/config.toml`, all 12 CLI commands (incl. opt-in `feedback`), map files, control identity, statuses, roles, and `map --changed` / `--full` |
| [`ci-gate.md`](ci-gate.md) | Gating pull requests in GitHub Actions with `brokenapp changes --fail-on` and Markdown PR comments |
| [`parity.md`](parity.md) | Comparing a legacy app against a rewrite or migration with `brokenapp parity` |
| [`safe-use-policy.md`](safe-use-policy.md) | Local-first enforcement, write-guard guarantees & caveats, credential boundaries, and authorized use |

## Repository References

| File | Purpose |
|---|---|
| [`../README.md`](../README.md) | Product overview, quick start, multi-stack table, and install methods |
| [`../ARCHITECTURE.md`](../ARCHITECTURE.md) | 17-module Rust architecture, process isolation, write guard, and diff engine |
| [`../AGENTS.md`](../AGENTS.md) | Fast orientation for AI coding agents working on this repo |
| [`../CLAUDE.md`](../CLAUDE.md) | Contributor build commands, module index, and Rust coding conventions |
| [`../agent/claude-code/SKILL.md`](../agent/claude-code/SKILL.md) | Concise agent skill installed by `brokenapp init` |
| [`../agent/AGENTS-snippet.md`](../agent/AGENTS-snippet.md) | Pasteable snippet for your app's `CLAUDE.md` or `AGENTS.md` |
| [`../examples/github-actions/pr-gate.yml`](../examples/github-actions/pr-gate.yml) | Copy-pasteable GitHub Actions PR gate workflow |
