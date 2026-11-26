# UI Map Reference

`brokenapp map` crawls your local web app in Chrome/Chromium over CDP with a mechanical write guard enabled by default. It exercises interactive buttons, links, tabs, modals, and forms under bounded `standard` defaults — or opt-in exhaustive `--full` mode — across the logged-out app and every configured login role, then writes greppable, diffable artifacts into `.brokenapp/map/`.

Read commands (`ui`, `dead`, `journey`, `changes`, `parity`) read saved files offline and never launch a browser or touch your running app.

## Project Setup (`.brokenapp/config.toml`)

Run `brokenapp init` once in your web app repository. It auto-detects the stack (Next.js, Vite, Astro, SvelteKit, Nuxt, Remix, Vue, Angular, Rails, Django, FastAPI, Flask, Laravel, Go, Spring Boot, ASP.NET, or static HTML), dev command, and port; writes `.brokenapp/config.toml` and `.brokenapp/.gitignore`; registers the project locally; and installs agent instructions (`--agent claude-code` writes `.claude/skills/brokenapp/SKILL.md`; `--agent agents-md` inserts an idempotent `<!-- brokenapp:start -->` block into `AGENTS.md`; `--agent all` writes both; `--agent none` skips).

```toml
# .brokenapp/config.toml (commit this file; never put secrets here)
[project]
name = "shop"
url = "http://127.0.0.1:3000"      # local by default; non-local requires scan.allow_remote = true
codebase = "."                      # relative to the parent of .brokenapp/
dev_cmd = "npm run dev"             # started automatically by `map` if url is unreachable
# dev_cwd = "apps/web"
# dev_env = { PORT = "3000", API_KEY = "env:SHOP_API_KEY" }  # env: references only
ready_timeout_secs = 120
protected = false                   # true = `map` refuses to scan (use on live-user repos)

[scan]
max_minutes = 10
max_views = 80
write_guard = "block"               # block (default) | stub | off
seed_from_source = true
headless = true
allow_remote = false
extra_routes = []                   # additional seeded routes (pinned past template saturation in --full)
exclude_routes = ["/logout"]        # route prefixes skipped during crawl & coverage
# max_interaction_depth = 2         # revealed-UI nesting depth (modals/wizards; 0-10; 4 in full mode)
# max_interactions_per_view = 25    # per-page control budget (1-1000; 1000 in full mode)
# max_interactions_per_depth = [1000, 250, 100, 50]  # per-nesting-depth cap (full mode default)
# settle_ms = 2000                  # post-action settle timeout
# tabs = 4                          # concurrent browser tabs (1-16)
# mode = "standard"                 # standard (default) | full (opt-in uncapped mode)
# max_hours = 6                     # optional wall-clock ceiling in full mode
# view_budget_seconds = 300         # per-view timeout (10-7200; default 300 in full mode)
# role_concurrency = 1              # roles crawled concurrently (sharing `tabs`)
# allowed_hosts = ["app.example.com", "*.example.com"]  # fail-closed host allowlist
# user_agent = "BrokenApp/0.1 (staging-qa)"             # custom User-Agent via CDP
# interaction_delay_ms = 500        # delay between UI interactions (ms)
# max_requests_per_second = 2.0     # polite cap on in-scope non-static HTTP requests/sec
# abort_on_rate_limits = 5          # abort with `rate_limited` after N HTTP 429s in 60s (default 5 when allow_remote=true)
# abort_on_antibot_challenges = 2   # abort with `antibot_challenge` after N WAF challenge pages (default 2 when allow_remote=true)
# [scan.extra_headers]              # stamped only on in-scope / allowed_hosts requests (never third-party origins)
# "X-QA-Runner" = "staging-ci"

# Optional deterministic local fixture inputs (NOT secrets; env: is not expanded here)
# [scan.test_data]
# "Find shipment" = ""

[auth]
include_anonymous = true            # map logged-out app at .brokenapp/map/ root

# Login roles (`brokenapp roles add <role>` manages these safely)
# [[roles]]
# name = "admin"
# method = "form"                   # form | session | cookie | bearer | supabase | firebase | manual
# login_url = "/sign-in"
# username = "env:ADMIN_EMAIL"
# password = "env:ADMIN_PASSWORD"
# check = "/api/me"                 # optional authenticated health probe
```

`init` refuses or externalizes inline secrets from `--dev-cmd` (`DATABASE_URL=...`, `*_KEY=...`, `*TOKEN*=...`, `*PASSWORD*=...`, including `/usr/bin/env` assignments) into `[project.dev_env]` as `"env:NAME"` references, syncs custom `--url` ports into auto-detected `dev_cmd`, and warns if an external `--state-dir` causes an absolute `codebase` path to be written into committable `config.toml`. Literal secrets inside `config.toml` are always rejected. Run `brokenapp doctor` to validate setup — it warns on unrecognized `.brokenapp/config.toml` keys and resumable interrupted runs, and never suggests destructive `init --force` on existing projects.

## Commands

| Command | Usage |
|---|---|
| `init` | `brokenapp init [--url URL] [--dev-cmd CMD] [--name NAME] [--codebase DIR] [--agent claude-code\|agents-md\|all\|none] [--protected] [--force] [--json]` |
| `roles` | `brokenapp roles list` · `brokenapp roles add <role> [--method M] [--login-url U] [--username-env V] [--password-env V] [--cookie-env V] [--token-env V] [--anon-key-env V] [--api-key-env V] [--submit-selector S] [--check P] [--json]` · `brokenapp roles remove <role>` |
| `login` | `brokenapp login --role <role> [--timeout SECS] [--no-start] [--json]` (interactive browser capture for `session`/`manual` roles, or verifies any configured role method; honors `ready_timeout_secs` + 1 cold-SSR retry on `--check`) |
| `map` | `brokenapp map [--changed [--since REF] [--force]] [--role R]... [--roles all\|none] [--route R]... [--no-merge] [--quick \| --full \| --mode standard\|full] [--resume] [--depth N] [--max-interactions N] [--view-budget SECS] [--tabs N] [--max-minutes N] [--max-views N] [--no-start] [--headed] [--allow-writes] [--json]` |
| `changes` | `brokenapp changes [--since N] [--between OLD NEW] [--role R\|all] [--format text\|md\|markdown\|json] [--fail-on LIST] [--json]` |
| `parity` | `brokenapp parity <baseline> <candidate> [--format text\|markdown\|json] [--fail-on LIST] [--json]` |
| `dead` | `brokenapp dead [--include-unexercised] [--role R\|all] [--inventory PATH] [--json]` |
| `ui` | `brokenapp ui [--route R] [--exact-route] [--exclude-shell] [--text T] [--status S] [--calls "METHOD /path"] [--kind K] [--role R\|all] [--inventory PATH] [--compact] [--format table\|tsv\|md\|json] [--json]` |
| `journey` | `brokenapp journey <route \| "METHOD /path" \| label:Text> [--from R] [--max-hops N] [--role R\|all] [--inventory PATH] [--format text\|md\|markdown\|json] [--json]` |
| `doctor` | `brokenapp doctor [--json]` |
| `projects` | `brokenapp projects [--json]` |
| `feedback` | `brokenapp feedback [<MESSAGE> \| --stdin] [--category bug\|ux\|auth\|crawler\|rbac\|journey\|other] [--agent NAME] [--include-stats] [--dry-run \| --send] [--opt-in \| --opt-out \| --status] [--endpoint URL] [--json]` |

- **Project targeting & environment variables:**
  - `BROKENAPP_HOME` — global registry & settings directory (`registry.json`, `settings.json`; default `~/.brokenapp`). In sandboxed or isolated runs where `~/.brokenapp` is unwritable, set `BROKENAPP_HOME=/tmp/brokenapp-home`.
  - `BROKENAPP_STATE_DIR` (`--state-dir <dir>`) / `--project <name>` — target a project outside the current directory; registered `--state-dir` projects are also auto-discovered when invoked inside their `root`, and `roles add` preserves `--state-dir` in printed next-step hints.
  - `BROKENAPP_CHROME_EXECUTABLE` (`BROKENAPP_CHROME` / `CHROME_PATH`) — override Chrome/Chromium discovery; `BROKENAPP_NO_SANDBOX=1` and `BROKENAPP_CHROME_ARGS` configure Linux/Docker headless launches.
  - `BROKENAPP_FEEDBACK_OPT_IN=1` / `BROKENAPP_FEEDBACK_URL` — session opt-in and endpoint override for strictly opt-in `brokenapp feedback`.
  - On monorepos, target a specific app workspace with `brokenapp init --codebase apps/<web-app>`.
- **Direct & portable inventory reads (`--inventory <PATH>`):** `ui`, `dead`, and `journey` accept `--inventory <PATH>` to inspect standalone `map --route --no-merge` partial snapshots (or `map --route` when no prior whole-app map exists) and historical `.inventory.json` files directly. When a whole-app map already exists, `map --route` merges the re-crawled routes into `latest.inventory.json`, refreshes `.brokenapp/map/` and `ROLE-ACCESS.md`, and saves the raw partial crawl under `history/partial/`. Without `--inventory`, readers check `history/latest.inventory.json` first and automatically fall back to committed `.brokenapp/map/ui-inventory.json` (and `map/roles/<role>/ui-inventory.json`) on fresh clones without `history/`.
- **JSON exit-1 contract:** Runtime/command errors on `--json`, `--compact`, and `--format json` commands print `{ "exit_code": 1, "status": "error", "error": "..." }` on stdout (plus the error on stderr); CLI argument-parse errors (such as unknown flags) exit `2` on stderr. Domain exit-1 results (`journey` unmatched, `changes`/`parity --fail-on` gate failure or `INCONCLUSIVE`) return their structured domain JSON instead.
- **`map --json` completion metadata:** Reports `stop_reason`, `queue_remaining`, `resolved_limits`, and actionable `next` commands per run (plus `stop_reason` and `queue_remaining` per role). `--max-minutes` applies **per role**; pass `--tabs 1` if a dev server stalls under parallel tabs.

## Generated Files (`.brokenapp/`)

```text
.brokenapp/
  config.toml                  commit — project settings and [[roles]] env: references
  credentials.toml             gitignored (mode 600) — local role values from `roles add`
  map/                         commit — greppable behavioral map
    UI-MAP.md                  per-route control table with observed outcomes & source file:line
    ui-map.tsv                 one tab-separated control per line (ideal for grep/awk)
    endpoints.tsv              endpoint -> triggering controls, on-load routes, and statuses
    DEAD-UI.md                 broken, dead, and no_effect controls with coverage caveats
    CHANGELOG.md               dated element-level & role-access change history (newest first)
    UI-MAP.html                standalone interactive HTML view for browser inspection
    ui-inventory.json          sanitized portable inventory for fresh-clone `ui`/`dead`/`journey`/`parity`
    README.md                  role index, last map timestamps, and coverage (when roles exist)
    ROLE-ACCESS.md             route x role & endpoints x role matrices, role-only controls, review flags
    role-access.tsv            machine-readable route, endpoint & control access matrix
    roles/<role>/              each role's UI-MAP.md, ui-map.tsv, endpoints.tsv, DEAD-UI.md, CHANGELOG.md, UI-MAP.html, ui-inventory.json
  history/                     gitignored — timestamped *.inventory.json snapshots (`brokenapp.inventory.v1`)
  scans/                       gitignored — raw CDP scan artifacts, run.json, map-progress.json
  session/                     gitignored — saved private browser sessions from `login --role`
```

## Control Identity & Statuses

Every control has a deterministic key `<route>|<role>|<locator>[#n]`, e.g. `/cart|button|testid=checkout` or `*|link|text=contact@footer`:

- **Locator preference:** `testid=` → non-generated `id=` → `aria=`/`name=` → normalized `text=` → `href=` (unlabeled links only).
- **Regions:** label locators carry landmark suffixes (`@header`, `@nav`, `@footer`, `@aside`, `@dialog`; main content has no suffix).
- **Global shell (`*`):** identical shell controls appearing on ≥60% of visited routes (at least 3) are grouped once under `*`.
- **Links:** `href` is recorded as an outcome (`navigates`), so retargeting a link reports `REWIRED` rather than `REMOVED` + `ADDED`. Note that probed link destinations verify reachability, not full click-through client execution.
- **Data folding:** digits, dates, and timestamps normalize to `#` so dynamic counters do not churn diffs.

| Status | Meaning | How to Treat It |
|---|---|---|
| `ok` | Exercised and produced an observable effect | Verify the effect is the *intended* behavior |
| `dead` | High confidence: exercised, no effect and no handler found | Real dead control or missing handler |
| `no_effect` | Exercised, handler exists, no visible effect | **Review the handler first** (may be already-active state, print, clipboard) |
| `broken` | Console/runtime error, HTTP ≥400, failed link, or repeated timeout (app-wrapped write-guard `Failed to fetch` aborts and browser-generated `chrome-error://` / `#reload-button` error pages are excluded) | Inspect `reason`; re-check isolated timeouts before assuming app failure |
| `not_exercised` | Not tried (budget limit, hidden, obscured — `obscured` reports top covering selectors) | **Never evidence it works.** Run `dead --include-unexercised` to inspect gaps |
| `skipped` | Intentionally skipped (logout, delete-like label, excluded route, file input) | Verify via code review |
| `disabled` / `external` | Disabled control / off-site link (not followed) | Informational |

`calls POST /api/orders (blocked)` confirms the control fires that request while the write guard stops it before reaching the backend; server-side effects after a blocked write are not observed. Periodic background polling and heartbeat keepalives (e.g. `setInterval` polls or `POST /api/session/renew`) are automatically detected and excluded from per-control attribution so consecutive `changes` and `parity` runs do not emit false `REWIRED` or `ENDPOINT REMOVED` diffs.

## Incremental Maps (`map --changed`) & Opt-In Exhaustive Scans (`map --full`)

- **`brokenapp map` (`standard` mode — fast default):** Runs with bounded defaults (`max_minutes = 10` per role, `max_views = 80`, `max_interaction_depth = 2`, `max_interactions_per_view = 25`). Pass `--quick` for a 3m / 25-view smoke pass, `--tabs 1` if a dev server stalls under parallel tabs, or `--view-budget 600` on dense single-route tabbed SPAs.
  - **Fast local dev crawling & warm-up:** On local scans, CDP `Fetch.enable` is scoped to write-capable resource types (`Document`, `Xhr`, `Fetch`, `EventSource`, `Ping`, `Other`) so static JS/CSS/font/image chunks load natively without pausing. Route warm-up passes available auth cookies/tokens so protected Next.js routes pre-compile before crawling (and suggests `next build && next start` if `next dev` warm-up exceeds 10s).
  - **Smart route prioritization:** Boosts the first concrete URL discovered for each unvisited dynamic `:id`/`:slug` template, collapses `/login?next=<route>` (`?redirect=`, `?returnTo=`) redirect loops into one canonical `/login` view, seeds each authenticated role's UI `--check` route first, and deprioritizes public routes already mapped identically under `anonymous`.
- **`brokenapp map --changed`:** Identifies files modified since the latest map (via git, or mtime without git), traces route files, layouts, transitive imports, mapped `source` sites, and API endpoints, and re-crawls only affected routes before merging them byte-for-byte into the previous inventory.
  - Skips the crawl completely (`exit 0`, top-level `"mode": "skipped"`, writes no new snapshot) when no UI routes are affected (tests, docs, unrelated files listed under `unmapped_files`). Inspect `map --changed --json` before running `changes`.
  - Automatically falls back to a **whole-app scan (with your selected budget)** on app-wide changes (framework config, middleware, root layout/entry, global CSS, ≥60% routes affected, or unattributed source/style changes). This does **not** switch into uncapped `--full` mode unless you explicitly pass `--full` or set `[scan] mode = "full"`.
- **`brokenapp map --full` (opt-in only; same as `--mode full`):** Deep/exhaustive mode for large SPAs, 100%-button/route audits, and multi-step wizards:
  - Removes global time/view caps (`[scan] max_hours` is an optional wall-clock ceiling) and disables convergence stopping.
  - Raises defaults to `max_interaction_depth = 4`, `max_interactions_per_view = 1000`, `max_interactions_per_depth = [1000, 250, 100, 50]`, and `view_budget_seconds = 300`.
  - Pins explicitly declared `extra_routes` past template saturation and reserves a 15s floor for nested passes so deep wizards do not starve.
  - Supports per-run CLI overrides: `--depth <0-10>` (raise to `6..10` for deep multi-step SPA wizards/modals), `--max-interactions <1-1000>`, and `--view-budget <10-7200>`.
  - Restarts a managed dev server if it crashes, checkpoints every ≤60s, and prints ETA progress (`map-progress.json`).
- **`brokenapp map --resume`:** Continues an interrupted run (exit `130`) **or** a budget-stopped `--full` run with `queue_remaining > 0` from its last checkpoint, keeping completed roles and continuing unfinished visits. Incremental `--changed` runs are not resumable; re-run them instead.

## Login Roles & Access Matrix (`ROLE-ACCESS.md`)

`map` runs an isolated scan subprocess per role (`anonymous` + every `[[roles]]` entry; `--max-minutes` applies per role). Credentials come strictly from `env:` references or mode-600 `.brokenapp/credentials.toml`, enter each subprocess through environment variables only, and are redacted from logs and JSON output. Verify any role method first with `brokenapp login --role <role> --json` before running `brokenapp map --role <role>`; for Next.js `@supabase/ssr` apps with custom cookie names, prefer `--method form` or `--method session`.

- A role that fails login, lacks credentials, has an expired session, or ends with a 0-route timeout (`timed_out_empty`) is skipped (`exit 3`, `status: partial`) while other roles finish. Its previous good map is preserved on disk (never overwritten by an empty timeout run), its `login_failed (<detail>)` reason is recorded in the `This run` column, and stale data is **excluded** from the freshly computed `ROLE-ACCESS.md`. Standalone `map --route` runs (with `--no-merge` or no existing map) leave `ROLE-ACCESS.md` untouched; merged `map --route` rescans refresh `ROLE-ACCESS.md`.
- `ROLE-ACCESS.md` reports:
  - **Route × Role matrix:** `visited`, `login`, `forbidden`, `redirected`, `error`, `not_linked`, `not_reached`, or `-`.
  - **Endpoints × Role matrix:** observed HTTP, GraphQL, and WebSocket (`WS /path#op`) endpoints per role (`allowed`, `write_guarded`, `forbidden`, `error`, `not_seen`, `-`), also emitted as `kind = endpoint` rows in `role-access.tsv`.
  - **Role-only controls:** controls present for some roles and absent for others on pages both visited (dark/light theme toggles are folded automatically so they do not clutter diffs).
  - **Review flags:** routes or endpoints reachable by a lower-privilege role name (`viewer`, `member`, `user`) while blocked (`login`/`forbidden`/`redirected`) for a higher-privilege role (`admin`, `owner`). Review flags are facts to inspect, not verdicts.
- `brokenapp changes --role all` reports both control regressions (`NOW DEAD`, `NOW BROKEN`, `REWIRED`, `REMOVED`, `ADDED`, `FIXED`, `ROUTE_CONTENT_MISSING`, `NOT_REACHED`) and multi-role access drift (`ACCESS GAINED`, `ACCESS LOST`, plus coverage-aware `ENDPOINT ACCESS GAINED` / `ENDPOINT ACCESS LOST` wired into `--fail-on access-gained,access-lost`). When `--fail-on` is set and the baseline map is missing, rebaselined, or either map visited `0` routes, `changes` returns `INCONCLUSIVE` (exit `1`) instead of falsely passing.

## Querying Efficiently (`ui` & `journey`)

- **Fresh clones without `.brokenapp/history/`:** `brokenapp ui`, `dead`, `journey`, and `parity` automatically fall back to committed `.brokenapp/map/ui-inventory.json` (and `map/roles/<role>/ui-inventory.json`), or `grep` committed `ui-map.tsv`, `UI-MAP.md`, `endpoints.tsv`, and `ROLE-ACCESS.md` directly.
- **Page-scoped inspection:** `brokenapp ui --route /orders/123 --exact-route --compact` (add `--exclude-shell` to omit header/nav/aside/footer controls; pass `--inventory <path>` to read a scoped `map --route` partial snapshot).
- **Concrete record/query states:** require recorded observation (`requested_state_observed: false` when unobserved; `unknown` stays `unknown`).
- **Opener-aware multi-step journeys (`brokenapp journey`):**
  - Traces **both** route navigations and in-page modal/drawer/tab/wizard opener chains (`state_entries` / `opened_by`) in the same role and concrete variant context.
  - Default `--max-hops` is `15` (raise e.g. `--max-hops 40` for long 25+ step customer journeys). Supports `--format text|md|markdown|json` (plus `--json` shorthand) and `--inventory <path>`.
  - Reports total steps, route hops vs. in-page steps, per-control-kind breakdown (e.g. `3 buttons, 1 link, 1 tab`), triggered endpoints with `[write blocked]` / HTTP status, broken/unexercised step flags, and `path_evidence`:
    - `stitched_candidate` — path stitched from independently observed transitions (not a single end-to-end replay)
    - `already_at_goal` — start route already matches the goal
    - `not_established` — goal exists in the map, but no path was observed within `--max-hops` (at low coverage, means "not observed", not "unreachable")
    - `unmatched` — no route, endpoint, or label matched the goal (exits `1`)

## Source Links & Limitations

- **Source links:** Dev builds with runtime debug frames and source maps (such as React 19 dev and Astro dev) yield `exact` runtime `file:line` (`render`, `caller`, `handler`). Other stacks use static candidate matching labeled `probable`, `guess`, or `ambiguous` — verify static candidates in source before editing.
- **Bounded coverage:** `standard` mode bounds time, views, interaction depth, and controls/view; opt-in `--full` removes global time/view caps and convergence stopping while retaining per-view budgets, depth limits, template sampling (outside pinned `extra_routes`), and safety skips. Probed link destinations are not the same as clicked execution. Always quote coverage denominators alongside any claim.
- **Single desktop viewport (1366×900):** Mobile-only UI is not mapped.
- **Write guard scope:** See [`safe-use-policy.md`](safe-use-policy.md) for what the guard stops (HTTP writes + structured mutating WebSocket frames) and its caveats (unrecognized GET-writes, Service Workers, binary/opaque WebSockets).

## Opt-In Agent Feedback (`brokenapp feedback`)

BrokenApp sends **zero silent telemetry**. If you want yourself or your AI coding agents to report CLI bugs, crawler edge cases, or UX friction to the BrokenApp triage queue, opt in explicitly:

```bash
# Persist opt-in in $BROKENAPP_HOME/settings.json (toggle off anytime with --opt-out)
brokenapp feedback --opt-in

# Preview the exact redacted JSON payload locally (zero network activity)
brokenapp feedback "Cold SSR check timed out" --category auth --agent claude-code --include-stats --dry-run

# Queue to https://brokenapp.io/api/feedback
brokenapp feedback "Cold SSR check timed out" --category auth --agent claude-code --include-stats --send
```

- **Hard consent gate:** Omitting `--send` (or passing `--dry-run`) **always** prints a local preview with zero network activity, even after `--opt-in` or `BROKENAPP_FEEDBACK_OPT_IN=1`. Agent-initiated calls (`--agent <name> --send`) additionally fail closed (`opt_in_required`, exit `1`) unless opted in.
- **Local redaction:** Messages are scrubbed locally for JWTs, API keys, `Bearer` tokens, `Cookie:` headers, URL credentials, and `/Users/<name>` home paths before leaving the machine.
- **Aggregate-only stats (`--include-stats`):** Attaches numeric counts aggregated across all mapped roles (`framework`, `scan_mode`, `routes_visited`, `routes_known`, `controls_exercised`, `controls_exercisable`, `dead`, `broken`, `no_effect`, `roles_count`, `roles_mapped`, `gap_reasons`) — never URLs, routes, labels, project names, or source code.
