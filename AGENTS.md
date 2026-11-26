# Agent Orientation

Fast path for coding agents working in the BrokenApp repository.

## What BrokenApp Is

BrokenApp is a **single zero-dependency Rust binary** (~108k LOC) that produces a git-diffable behavioral and multi-role access map for any local web app:

- **12 public commands:** `init`, `roles`, `login`, `map`, `changes`, `parity`, `dead`, `ui`, `journey`, `doctor`, `projects`, `feedback`.
- **1 config file:** `.brokenapp/config.toml` (secrets live only in `env:` variables or `chmod 600` gitignored `.brokenapp/credentials.toml`).
- **Greppable & portable output:** `.brokenapp/map/` (`UI-MAP.md`, `ui-map.tsv`, `endpoints.tsv`, `DEAD-UI.md`, `ROLE-ACCESS.md`, `role-access.tsv`, `CHANGELOG.md`, `UI-MAP.html`, `ui-inventory.json`, plus per-role maps under `roles/<role>/`).
- **Mechanical write guard & privacy:** CDP request interception blocks non-`GET`/`HEAD`/`OPTIONS` writes, GraphQL mutations, beacons, and form POSTs by default, and in-page `WebSocket.prototype.send` guarding stops structured mutating WebSocket frames while allowing reads/subscriptions/heartbeats (caveat: unrecognized GET-based writes, Service Workers, and background opaque WebSocket frames stay outside the guard; printed at scan start). Raw API response bodies are omitted from `network.jsonl` by default (`output.include_response_bodies = false`), and browser-generated error documents (`chrome-error://`, `#reload-button`) are excluded from route/control discovery.

## Repository Map

| Path | Purpose |
|---|---|
| `src/` | 17-module Rust crate + `src/main.rs` entrypoint |
| `tests/` | Integration tests and local HTTP/UI fixtures |
| `agent/claude-code/SKILL.md` | Concise (≤75-line) skill embedded into `brokenapp init` |
| `agent/AGENTS-snippet.md` | Pasteable snippet for target repos' `CLAUDE.md` / `AGENTS.md` |
| `docs/` | User docs (`README.md`, `ui-map.md`, `ci-gate.md`, `parity.md`, `safe-use-policy.md`) |
| `examples/github-actions/pr-gate.yml` | Copy-pasteable GitHub Actions PR gate workflow |
| `Dockerfile`, `install.sh`, `homebrew/` | Container, shell installer, and Homebrew packaging |
| `.github/workflows/` | `ci.yml` (Rust + Chromium integration + docs/link checks) and `release.yml` (cross-platform builds + `.sha256` checksums) |

## Verification Commands

Run the narrowest checks that prove your change (Rust 1.88+ / edition 2024):

```bash
cargo fmt --check
cargo clippy --all-targets --locked
cargo test --locked --lib
cargo test --locked --bin brokenapp
cargo test --locked --test integration_tests -- --test-threads=2 write_guard_test ws_toast_modal_test compliance_guardrails_test   # requires Chrome/Chromium
cargo audit   # 0 vulnerabilities target
cargo run -- doctor --json
```

For docs-only edits, verify local links and whitespace (`git diff --check`).

## Source-of-Truth Docs

- [`README.md`](README.md) — product overview, quick start, 12 commands, multi-stack table, install
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — 17-module Rust architecture, process isolation, write guard, diff/parity design
- [`CLAUDE.md`](CLAUDE.md) — Rust coding conventions and module index
- [`agent/claude-code/SKILL.md`](agent/claude-code/SKILL.md) — agent operating loop for target apps
- [`docs/ui-map.md`](docs/ui-map.md) — config, commands, map files, statuses, roles, and `--changed`
- [`docs/ci-gate.md`](docs/ci-gate.md) — `brokenapp changes --fail-on` in CI
- [`docs/parity.md`](docs/parity.md) — `brokenapp parity` for rewrites and migrations
- [`docs/safe-use-policy.md`](docs/safe-use-policy.md) — write-guard boundaries and authorized use

## Non-Negotiable Boundaries

- One browser stack (`chromiumoxide` CDP) and zero external runtime services (no DB daemon, no Node runtime, no cloud coupling).
- Only scan local/authorized targets; never weaken write-guard defaults, `protected = true`, or credential redaction.
- Be honest about coverage (`not_exercised` ≠ working) and write-guard caveats (unrecognized GET-writes, Service Workers, binary/opaque WebSockets).
