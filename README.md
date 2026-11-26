<p align="center">
  <img src="logo.png" alt="BrokenApp" width="200" />
</p>

<h1 align="center">BrokenApp</h1>

<p align="center">
  <strong>A map of what your web app actually does, per login role, traced to the line of code — for you and your coding agent to query and diff.</strong>
</p>

<p align="center">
  <a href="#quick-start">Quick Start</a> &middot;
  <a href="#commands">Commands</a> &middot;
  <a href="#deep-spa-audits--customer-journeys">Deep SPAs &amp; Journeys</a> &middot;
  <a href="#role-access--ci-pr-gate">Role Access &amp; CI Gate</a> &middot;
  <a href="#legacy--rewrite-parity">Parity</a> &middot;
  <a href="#how-the-write-guard-works">Write Guard</a> &middot;
  <a href="#multi-stack-support">Multi-Stack</a> &middot;
  <a href="#install">Install</a> &middot;
  <a href="docs/README.md">Docs</a>
</p>

---

BrokenApp is a **single zero-dependency Rust binary** (~108k LOC — no Node runtime, no database daemon, no cloud account). It drives your local web app in Chrome over CDP with a mechanical write guard on by default, exercises interactive buttons, links, tabs, modals, and forms across every configured login role (fast bounded default or opt-in exhaustive `--full` mode), and writes a greppable, diffable behavioral map in `.brokenapp/map/`.

```text
$ brokenapp map --changed && brokenapp changes --role all --fail-on dead,broken,access-gained

Re-crawled 2 affected routes (changed: src/app/checkout/page.tsx, src/middleware.ts)
Coverage: 41/44 exercisable controls exercised (93%), 14/14 routes visited

== anonymous ==
  NOW DEAD   /checkout button "Pay now" (was calls POST /api/orders)
  REWIRED    * link "Pricing": -> /contact (was -> /pricing)

== member ==
  ACCESS GAINED  member /admin (was forbidden)

== admin ==
  (no behavioral changes)

CI gate failed (--fail-on dead,broken,access-gained): 2 violations (1 dead, 1 access-gained)
exit status 1
```

Commit `.brokenapp/map/` alongside your code so both humans in PR review and AI coding agents see what every observed control actually does — and what just broke or drifted across roles.

## Quick Start

Requires Chrome or Chromium installed locally (`brokenapp doctor` checks your setup).

```bash
# 1. Detect your stack, dev command, and port; write .brokenapp/config.toml
cd my-web-app
brokenapp init

# 2. Run a write-guarded crawl across anonymous + every configured login role
brokenapp map

# 3. After editing code, re-crawl only affected routes and diff behavior + RBAC
brokenapp map --changed
brokenapp changes --role all
```

`brokenapp map` writes greppable artifacts into `.brokenapp/map/`:

- `UI-MAP.md` & `ui-map.tsv` — observed routes, controls, outcomes, statuses, and source `file:line`
- `endpoints.tsv` — which controls and routes call each HTTP/GraphQL/WebSocket endpoint
- `DEAD-UI.md` — high-confidence dead, broken, and no-effect controls with explicit coverage caveats
- `ROLE-ACCESS.md` & `role-access.tsv` — route × role and endpoints × role matrices, per-role control differences, and review flags
- `CHANGELOG.md` — dated behavioral and access diff history
- `UI-MAP.html` — standalone interactive HTML report for browser review
- `ui-inventory.json` — sanitized portable inventory (local `scan_dir` stripped) so `ui`, `dead`, `journey`, and `parity` work on fresh clones without `.brokenapp/history/`

## Commands

One config file (`.brokenapp/config.toml`), 12 focused commands:

| Command | Purpose | Key Flags |
|---|---|---|
| `brokenapp init` | Auto-detect framework, dev command, and port (syncing custom `--url` ports); write `.brokenapp/config.toml` and install agent instructions | `--url`, `--dev-cmd`, `--codebase`, `--name`, `--agent claude-code\|agents-md\|all\|none`, `--protected`, `--force`, `--json` |
| `brokenapp roles` | Manage login roles (`list`, `add <role>`, `remove <role>`) with zero secrets in `config.toml` | `--method`, `--login-url`, `--username-env`, `--password-env`, `--cookie-env`, `--token-env`, `--submit-selector`, `--check`, `--json` |
| `brokenapp login` | Save an interactive browser session (SSO/MFA) or verify any configured role (honors `ready_timeout_secs` + cold-SSR retry) | `--role <role>`, `--timeout`, `--no-start`, `--json` |
| `brokenapp map` | Run a write-guarded multi-role CDP crawl and refresh `.brokenapp/map/` | `--changed`, `--role`, `--roles none`, `--route`, `--no-merge`, `--quick`, `--full`, `--resume`, `--depth`, `--max-interactions`, `--view-budget`, `--tabs`, `--no-start`, `--headed`, `--allow-writes`, `--json` |
| `brokenapp changes` | Behavioral + multi-role access diff vs previous map; CI exit-code gate | `--since N`, `--between OLD NEW`, `--role <name\|all>`, `--format text\|md\|markdown\|json`, `--fail-on`, `--json` |
| `brokenapp parity` | Cross-app behavioral & RBAC parity check (`<baseline> <candidate>`) | `--format text\|markdown\|json`, `--fail-on`, `--json` |
| `brokenapp dead` | High-confidence dead, broken, and no-effect controls with honest coverage denominators | `--include-unexercised`, `--role <name\|all>`, `--inventory <PATH>`, `--json` |
| `brokenapp ui` | Offline query over saved maps (no browser launched) | `--route`, `--exact-route`, `--exclude-shell`, `--text`, `--status`, `--calls`, `--kind`, `--role`, `--inventory <PATH>`, `--compact`, `--format table\|tsv\|md\|json`, `--json` |
| `brokenapp journey` | Multi-step paths across routes and in-page modals/tabs/wizards to a route, endpoint, or `label:<text>` | `--from`, `--max-hops` (default `15`), `--role <name\|all>`, `--inventory <PATH>`, `--format text\|md\|markdown\|json`, `--json` |
| `brokenapp doctor` | Validate binary, PATH, Chrome, `.brokenapp/config.toml` (including unknown keys), resumable runs, target reachability, and role readiness | `--json` |
| `brokenapp projects` | List locally registered projects and their latest map summaries | `--json` |
| `brokenapp feedback` | Strictly opt-in: preview locally (default / `--dry-run`) or queue sanitized human/agent bug & UX reports with explicit `--send` (zero silent telemetry) | `--category`, `--agent`, `--include-stats`, `--dry-run`, `--send`, `--opt-in`, `--opt-out`, `--status`, `--json` |

Runtime/command errors on `--json`, `--compact`, and `--format json` commands emit `{ "exit_code": 1, "status": "error", "error": "..." }` on stdout (plus the error on stderr); CLI argument-parse errors (such as unknown flags) exit `2` on stderr. Domain exit-1 results (`journey` unmatched, `changes`/`parity --fail-on` gate failure or `INCONCLUSIVE`) return their structured domain JSON. Pass `--inventory <PATH>` to `ui`, `dead`, or `journey` to read standalone `map --route --no-merge` partial snapshots or historical inventories directly.

## Deep SPA Audits & Customer Journeys

`brokenapp map` defaults to fast, bounded **`standard` mode** (10m / 80 views, depth 2, 25 controls/view). When you explicitly want an exhaustive SPA audit or deep multi-step wizard coverage, opt into `--full`:

```bash
# Opt-in exhaustive mode (no global time/view caps; convergence stopping disabled)
brokenapp map --full --depth 8 --view-budget 600

# Resume an interrupted or budget-stopped --full run (queue_remaining > 0)
brokenapp map --resume

# Trace multi-step customer journeys across both route hops and in-page modals/tabs/wizards
brokenapp journey "POST /api/orders" --role member --max-hops 40 --format md
```

- **`--full` (same as `--mode full`)** raises defaults to `max_interaction_depth = 4`, `max_interactions_per_view = 1000`, `max_interactions_per_depth = [1000, 250, 100, 50]`, `view_budget_seconds = 300`, pins explicitly declared `extra_routes` past template saturation, and guarantees a 15s floor for nested passes so deep wizards do not starve.
- **`map --json`** reports `stop_reason`, `queue_remaining`, `resolved_limits`, and actionable `next` commands per run (plus `stop_reason` / `queue_remaining` per role).
- **`brokenapp journey`** traces both route navigations and in-page modal/drawer/tab/wizard opener chains in the same role and concrete variant context, reporting total steps, route hops vs. in-page steps, per-control-kind breakdown (e.g. `3 buttons, 1 link, 1 tab`), triggered endpoints with `[write blocked]` / HTTP status, broken/unexercised flags, and `path_evidence` (`stitched_candidate`, `already_at_goal`, `not_established`, or `unmatched`).

## Role Access & CI PR Gate

Configure any number of login roles (`form`, `session` for SSO/MFA, `cookie`, `bearer`, `supabase`, `firebase`, `manual`):

```bash
brokenapp roles add admin --login-url /sign-in    # hidden prompt -> mode-600 gitignored .brokenapp/credentials.toml
brokenapp roles add member --login-url /sign-in --username-env MEMBER_EMAIL --password-env MEMBER_PASSWORD
brokenapp roles add sso --method session && brokenapp login --role sso
brokenapp login --role admin --json                # verify any role method before mapping
brokenapp map                                      # maps anonymous + admin + member + sso (--max-minutes applies per role)
```

Literal secrets in `.brokenapp/config.toml` are rejected. Credentials live in `env:` shell variables or `.brokenapp/credentials.toml` (`chmod 600`, gitignored), enter scan subprocesses strictly through environment variables, and are redacted from all logs and JSON output.

Gate pull requests on behavioral regressions and RBAC drift in GitHub Actions:

```bash
brokenapp changes --role all \
  --fail-on dead,broken,access-gained,access-lost \
  --format markdown
```

- Supported `--fail-on` categories: `dead`, `broken`, `no-effect`, `rewired`, `removed`, `route-removed`, `endpoint-removed`, `access-gained`, `access-lost`, `any` (exits `1` on violation).
- Missing or rebaselined baselines — or `0` visited routes on either map — return `INCONCLUSIVE` (exit `1`) with `--fail-on` rather than falsely passing.
- Copy-pasteable PR workflow (runs crawl, posts a sticky Markdown diff comment, uploads `UI-MAP.html`): [`examples/github-actions/pr-gate.yml`](examples/github-actions/pr-gate.yml).
- Full CI gate guide: [`docs/ci-gate.md`](docs/ci-gate.md).

## Legacy & Rewrite Parity

Rewriting a legacy monolith, upgrading a framework, or replacing a frontend with AI-generated code? Map both apps and run `brokenapp parity`:

```bash
brokenapp parity ./legacy-app/.brokenapp/map ./new-app/.brokenapp/map \
  --format markdown \
  --fail-on dead,broken,access-gained
```

`parity` compares two saved map directories across all matching roles and reports:

- Missing routes and missing API endpoints
- Missing or regressed controls (`NOW DEAD`, `NOW BROKEN`, `REWIRED`)
- Multi-role access drift (`ACCESS GAINED` / `ACCESS LOST`)

See [`docs/parity.md`](docs/parity.md) for migration workflows and CI gating.

## How the Write Guard Works

Before the crawler navigates to any page, BrokenApp attaches a CDP network interceptor (`scan.write_guard = "block"` by default; also supports `stub` and `off`):

1. **Intercepted and stopped before hitting your backend:** non-`GET`/`HEAD`/`OPTIONS` HTTP requests (`POST`, `PUT`, `PATCH`, `DELETE`), GraphQL mutations, beacons, form `POST`s, and structured mutating WebSocket frames (RPC/GraphQL/command mutations via in-page `WebSocket.prototype.send` guarding, while allowing read/subscribe/heartbeat frames). On local scans, CDP `Fetch.enable` is scoped to write-capable resource types (`Document`, `Xhr`, `Fetch`, `EventSource`, `Ping`, `Other`) so static JS/CSS/font/image chunks load at native speed without pausing.
2. **Recorded cleanly without false positives:** the triggering control is recorded as `calls POST /api/orders (blocked)` or `calls WS /ws#server.updateSettings (blocked)`, confirming client wiring without mutating your database, and app-wrapped `console.error` or generic network-abort toast noise caused solely by a write-guard block is suppressed from `DEAD-UI.md` `Broken`. Background polling/heartbeats (e.g., periodic `setInterval` fetches or `POST /api/session/renew`) are also excluded from per-control attribution so `changes` and `parity` stay deterministic.
3. **Narrow exceptions:** only same-origin form-login authentication flows (NextAuth, Better Auth, custom login POSTs during sign-in) and explicit `[scan] write_guard_allow` patterns (for example `POST */api/graphql` to let GraphQL read queries run while GraphQL mutations stay blocked, or `WS` patterns) pass through.
4. **Local-only default & privacy:** non-local URLs are refused unless `scan.allow_remote = true` is explicitly set; projects with `protected = true` are always refused. Raw API response bodies are omitted from `network.jsonl` by default (`output.include_response_bodies = false`), and any retained snippets or schema samples are scrubbed before serialization.

**Honest caveats:**

- **Outside the guard:** state changes triggered via unrecognized `GET` routes, Service Worker-intercepted traffic, and binary or custom/opaque background WebSocket frames are not blocked by the guard. `brokenapp map` prints these guard limits at scan start; use disposable data or `scan.exclude_routes`.
- **Unobserved server aftermath:** in `block` mode, server-side validation errors or post-write confirmation pages are not reached because the write never ran.
- **Interactive capture:** `brokenapp login --role <name>` for `session`/`manual` roles opens a normal unguarded browser solely for human sign-in; subsequent crawls run guarded.
- Never pass `--allow-writes` unless the backend runs against disposable local data. See [`docs/safe-use-policy.md`](docs/safe-use-policy.md).

## For AI Coding Agents

`brokenapp init` installs a concise agent skill into `.claude/skills/brokenapp/SKILL.md` by default (`--agent claude-code`), or pass `--agent agents-md` / `--agent all` to install an idempotent `<!-- brokenapp:start -->` block into `AGENTS.md` (sources: [`agent/claude-code/SKILL.md`](agent/claude-code/SKILL.md), [`agent/AGENTS-snippet.md`](agent/AGENTS-snippet.md)).

- **Read before scanning (offline):** agents query committed `.brokenapp/map/` (`ui-inventory.json`, `ui-map.tsv`, `ROLE-ACCESS.md`) on fresh clones via `brokenapp ui`, `dead`, `journey`, and `parity` (or direct `grep`) without launching a browser; pass `--inventory <path>` for standalone `map --route --no-merge` snapshots.
- **Verify after edits:** `brokenapp map --changed --json` checks only impacted routes (falling back to a whole-app scan with your selected budget on app-wide edits), reports top-level `mode` (`"skipped"`, `"incremental"`, or `"full"`), `stop_reason`, `queue_remaining`, and `next`, and pairs with `brokenapp changes --role all`.
- **Honest coverage:** `not_exercised` is never reported as working (`obscured` gaps report the top covering selectors), probed link destinations are not clicked execution, stitched journeys are not E2E replays, and coverage denominators travel with every result.
- **Strictly opt-in agent feedback:** BrokenApp sends zero silent telemetry. If you explicitly opt in (`brokenapp feedback --opt-in` or `BROKENAPP_FEEDBACK_OPT_IN=1`), coding agents can submit locally redacted CLI bug/UX reports via `brokenapp feedback "..." --category bug|ux|auth|crawler|rbac|journey --agent <name> --include-stats --send` (preview anytime with `--dry-run`).

## Multi-Stack Support

| Capability | Supported Stacks | Notes |
|---|---|---|
| **Runtime crawl, write guard, multi-role RBAC, diff, parity, dead UI, journeys** | **Every web app Chrome can render** | Framework-agnostic CDP execution over HTTP |
| **Auto-detection (`brokenapp init`) & route discovery** | Next.js, Vite, Astro, SvelteKit, Nuxt, Remix, Vue, Angular, Rails, Django, FastAPI, Flask, Laravel, Go, Spring Boot, ASP.NET, static HTML | Detects dev command, port, and concrete route seeds; override anytime with `--url` / `--dev-cmd` / `extra_routes` |
| **Exact runtime `file:line` source attribution** | JS/TS dev servers with debug frames & source maps (e.g., React 19 dev builds, Astro dev) | Resolved live via source maps while dev server is up |
| **Static source candidate matching** | All stacks | Labeled honestly as `probable`, `guess`, or `ambiguous` — verify in source before editing |

## Install

**Prerequisite:** Google Chrome or Chromium (`BROKENAPP_CHROME_EXECUTABLE`, `BROKENAPP_CHROME`, or `CHROME_PATH` to override). In sandboxed or isolated environments where `~/.brokenapp` is unwritable, set `BROKENAPP_HOME=/tmp/brokenapp-home`.

```bash
# Prebuilt binary (Linux & macOS, verifies SHA-256 checksum)
curl -fsSL https://raw.githubusercontent.com/BrokenAppio/brokenapp/main/install.sh | bash

# Homebrew
brew install --formula https://raw.githubusercontent.com/BrokenAppio/brokenapp/main/homebrew/brokenapp.rb

# From source (Rust 1.88+ / edition 2024)
cargo install --git https://github.com/BrokenAppio/brokenapp

# Docker (bundles Chromium + container-safe defaults)
docker build -t brokenapp .
docker run --rm --network host -v "$PWD:/work" -w /work brokenapp doctor
```

Verify your install:

```bash
brokenapp doctor
```

## Docs

- [`docs/README.md`](docs/README.md) — Documentation index
- [`docs/ui-map.md`](docs/ui-map.md) — Config, commands, map files, statuses, roles, journeys, and `--changed` / `--full`
- [`docs/ci-gate.md`](docs/ci-gate.md) — GitHub Actions PR gate with `brokenapp changes --fail-on`
- [`docs/parity.md`](docs/parity.md) — Cross-app behavioral & RBAC parity for rewrites and migrations
- [`docs/safe-use-policy.md`](docs/safe-use-policy.md) — Write-guard guarantees, caveats, and authorized-use policy
- [`ARCHITECTURE.md`](ARCHITECTURE.md) — 17-module Rust architecture for contributors

## License

[MIT](LICENSE)
