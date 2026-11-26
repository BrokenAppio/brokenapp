# CLAUDE.md — Contributor & AI Agent Instructions for BrokenApp

## Project Overview

BrokenApp is a single zero-dependency Rust binary (~108k LOC) that builds a write-guarded behavioral map and multi-role diff of any local web app over Chrome DevTools Protocol (CDP).

- **Binary:** `brokenapp` (`cargo run -- ...`).
- **Runtime dependency:** Chrome or Chromium locally (`BROKENAPP_CHROME` / `CHROME_PATH` overrides detection).
- **Config surface:** One project file, `.brokenapp/config.toml` (secrets live strictly in `env:` shell references or mode-600 gitignored `.brokenapp/credentials.toml`).
- **Public CLI (12 commands):** `init`, `roles`, `login`, `map`, `changes`, `parity`, `dead`, `ui`, `journey`, `doctor`, `projects`, `feedback` (plus hidden internal crawl workers `scan` and `resume` in `src/main.rs`).

Read [`AGENTS.md`](AGENTS.md) and [`ARCHITECTURE.md`](ARCHITECTURE.md) before making structural changes.

## Build & Verification (Rust 1.88+ / Edition 2024)

```bash
cargo fmt --check
cargo clippy --all-targets --locked
cargo test --locked --lib
cargo test --locked --bin brokenapp
cargo test --locked --test integration_tests -- --test-threads=2 write_guard_test ws_toast_modal_test compliance_guardrails_test   # requires local Chrome/Chromium
cargo audit
cargo run -- doctor --json
```

## Rust Module Layout (17 Modules in `src/lib.rs`)

| Module | Path | Responsibility |
|---|---|---|
| `browser` | `src/browser/` | Chrome/Chromium launch, CDP `PageClient`, tab pool, settle helpers |
| `bugs` | `src/bugs/` | Runtime bug detection (dead buttons, broken links, console/server errors, form validation, accessibility, passive headers, templates) |
| `code_link` | `src/code_link/` | Element → source `file:line` via runtime dev frames/source maps + static candidate fallback |
| `config` | `src/config.rs` | Internal scan TOML config schema and validation |
| `dom` | `src/dom/` | Element discovery, classification, interaction, fingerprinting, DOM snapshots |
| `explorer` | `src/explorer/` | Crawl loop, priority scheduler, route-template sampling, route seeds, coverage, checkpoint/resume, interrupts |
| `finding_judgment` | `src/finding_judgment.rs` | Finding confidence and evidence-completeness scoring |
| `front` | `src/front/` | Public 12-command CLI (incl. opt-in `feedback`), framework detection, dev-server supervisor, auth-aware warmup, role orchestration, `--changed` impact analysis, secrets/redaction |
| `inventory` | `src/inventory/` | `brokenapp.inventory.v1` read model, stable control identity, diff, parity, journey BFS, Markdown/TSV/HTML rendering |
| `network` | `src/network/` | CDP network interception, write-guard enforcement, egress filter, GraphQL inspection, path parameterization |
| `output` | `src/output/` | Deterministic scan artifact writers (`spec.json`, `checkpoint.json`, `coverage-gaps.json`, bug reports) |
| `route_discovery` | `src/route_discovery/` | Static route extraction across frameworks for seeding and coverage |
| `safety` | `src/safety.rs` | Write-guard policy (`Read` / `Allowed` / `Guard`) and production-host safety gates |
| `scope` | `src/scope.rs` | Route, endpoint, and component include/exclude filters |
| `session` | `src/session/` | Guarded form login, browser storage-state capture/restore, health probes, auth providers |
| `types` | `src/types/` | Shared DOM, API, bug, classifier, and graph types |
| `url_origin` | `src/url_origin.rs` | Same-origin and localhost-alias (`localhost` / `127.0.0.1` / `0.0.0.0` / `::1`) matching |

Entrypoint: `src/main.rs` (`Cli`, hidden `InternalScan` / `InternalResume` workers).
Embedded skill: `agent/claude-code/SKILL.md` is compiled into `src/front/init.rs` via `include_str!`.

## Coding Conventions

- Use `anyhow::Result` with `.context("...")` on fallible I/O and parsing.
- Use `BTreeMap` / `BTreeSet` for serialized maps and sets so generated artifacts and diffs stay deterministic.
- Use `#[serde(default, skip_serializing_if = "Option::is_none")]` where compact JSON output matters.
- Use `env!("BROKENAPP_BUILD_VERSION")` for CLI version display (set by `build.rs`).
- Write artifacts via `crate::output::write_json()` / `write_text()` where available.
- Register new top-level modules alphabetically in `src/lib.rs`.
- Route all browser interaction through `BrowserManager` / `PageClient` (`chromiumoxide`). Do not introduce a second browser engine.
- Keep BrokenApp a single zero-runtime-dependency Rust crate — do not add database daemons, Node runtimes, or cloud dependencies.
- Keep `agent/claude-code/SKILL.md` concise (target 50–65 lines, CI cap 75 lines).

## Safety & Documentation Rules

- Never weaken local-only defaults, `protected = true` enforcement, write-guard blocking, or secret redaction.
- Never log, serialize, or commit literal credentials or saved browser session files.
- Keep `README.md`, `ARCHITECTURE.md`, `AGENTS.md`, `agent/`, and `docs/` strictly aligned with the real CLI surface and honest about coverage and write-guard caveats.
