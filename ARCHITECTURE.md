# Architecture

BrokenApp is a **single zero-dependency Rust crate** compiled to one binary (`brokenapp`). Its only runtime dependency is a local Chrome or Chromium executable driven over Chrome DevTools Protocol (CDP).

## End-to-End Runtime Flow

```text
.brokenapp/config.toml + CLI (`src/front/`)
  │
  ├─► init / detect       Stack & port auto-detection, secret externalization, embedded SKILL.md
  ├─► roles / login       env: / mode-600 credentials.toml, interactive browser session capture
  ├─► dev supervisor      Auto-start & crash-restart `dev_cmd`, concurrent route warm-up
  ├─► --changed analysis  git/mtime diff -> route/import/API impact -> scoped recrawl or full fallback
  │
  ▼  (one isolated `brokenapp scan` / `resume` subprocess per role)
BrowserManager / PageClient (`src/browser/`)
  ├─► Write Guard         CDP Fetch interception before navigation (`src/safety.rs`, `src/network/interceptor.rs`)
  ├─► Session Auth        Guarded form login or private storage-state restore (`src/session/`)
  ├─► Explorer Engine     BFS scheduler, template sampler, route seeds, checkpoint/resume (`src/explorer/`)
  ├─► DOM & Bugs          Discovery, classification, interaction, snapshots, findings (`src/dom/`, `src/bugs/`)
  ├─► Source Attribution  Runtime dev frames + source maps, static candidate fallback (`src/code_link/`)
  └─► Raw Artifacts       `spec.json`, `network.jsonl`, `checkpoint.json` (`src/output/`)
  │
  ▼  (parent process builds & persists map)
Inventory Engine (`src/inventory/`)
  ├─► Stable Identity     `<route>|<role>|<locator>` + landmark regions + link targets as outcomes
  ├─► Diff & CI Gate      `changes` (control regressions + ACCESS GAINED/LOST + `--fail-on`)
  ├─► Cross-App Parity    `parity <baseline> <candidate>` (routes, endpoints, controls, RBAC)
  ├─► Reverse Journeys    `journey <route | endpoint | label:...>` shortest hop paths
  └─► Greppable Renders   `.brokenapp/map/`: UI-MAP.md, ui-map.tsv, endpoints.tsv, DEAD-UI.md,
                          ROLE-ACCESS.md, role-access.tsv, CHANGELOG.md, UI-MAP.html, ui-inventory.json
```

## Module Index (17 Modules in `src/lib.rs`)

| Module | Key Files | Responsibility |
|---|---|---|
| `browser` | `mod.rs`, `page.rs`, `pool.rs`, `cdp_helpers.rs` | Chrome/Chromium process management, CDP `PageClient`, concurrent tab pool, DOM/network settle |
| `bugs` | `detector.rs`, `ui_errors.rs`, `dead_buttons.rs`, `broken_links.rs`, `console_errors.rs`, `server_errors.rs`, `form_validation.rs`, `accessibility.rs`, `passive_headers.rs`, `runtime_templates.rs` | Runtime finding detection, UI error toast/modal classification, and passive response checks |
| `code_link` | `mod.rs`, `runtime_source.rs`, `static_source.rs` | Maps controls/errors to `file:line` via runtime dev stacks/source maps with static fallback |
| `config` | `src/config.rs` | Internal crawl configuration model passed from `map` to isolated scan subprocesses |
| `dom` | `discovery.rs`, `classifier.rs`, `interaction.rs`, `effects.rs`, `fingerprint.rs`, `snapshot.rs`, `selector.rs` | Interactive element discovery, safe clicking/filling, effect observation, DOM snapshots |
| `explorer` | `engine.rs`, `scheduler.rs`, `template_sampler.rs`, `route_seeds.rs`, `url_utils.rs`, `coverage.rs`, `interrupt.rs`, `run_report.rs` | Crawl loop, priority scheduler (dynamic template boost & auth deprioritization), login-redirect URL canonicalization, browser error-doc filtering (`chrome-error://`), route-template sampling, checkpoint/resume, graceful SIGINT/SIGTERM |
| `finding_judgment` | `src/finding_judgment.rs` | Evidence-completeness and confidence labeling for detected bugs |
| `front` | `mod.rs`, `init.rs`, `detect.rs`, `map.rs`, `changed.rs`, `changes_gate.rs`, `impact.rs`, `read.rs`, `roles.rs`, `roles_cmd.rs`, `role_access.rs`, `login_check.rs`, `process.rs`, `project.rs`, `projects.rs`, `doctor.rs`, `feedback.rs`, `run_state.rs`, `secrets.rs`, `warmup.rs`, `locality.rs` | Public 12-command CLI (`init`, `roles`, `login`, `map`, `changes`, `parity`, `dead`, `ui`, `journey`, `doctor`, `projects`, `feedback`), CI gate policy, and run orchestration |
| `inventory` | `build.rs`, `identity.rs`, `diff.rs`, `merge.rs`, `query.rs`, `journey.rs`, `render.rs`, `artifacts.rs`, `evidence.rs` | `brokenapp.inventory.v1` model, stable control keys, background polling/heartbeat exclusion, behavioral & RBAC diffs, incremental merges, parity, map renderers |
| `network` | `interceptor.rs`, `egress.rs`, `graphql.rs`, `path_parameterizer.rs`, `schema_inference.rs`, `filters.rs` | Scoped CDP request interception, write-guard blocking/stubbing, `AuthWriteScope`, GraphQL mutation detection, polling/heartbeat & static-asset filters, endpoint normalization |
| `output` | `mod.rs`, `spec_generator.rs`, `checkpoint.rs`, `interactions.rs`, `coverage_gap.rs`, `bug_report.rs` | Deterministic JSON/Markdown writers for raw scan artifacts |
| `route_discovery` | `mod.rs`, `file_routers.rs`, `config_routers.rs`, `next.rs`, `server.rs`, `static_params.rs`, `paths.rs` | Static route discovery across JS/TS and server-side frameworks for seeding and coverage denominators |
| `safety` | `src/safety.rs` | Write-guard decision policy (`WriteVerdict`: `Read`, `Allowed`, `Guard`) and production-host safety gates |
| `scope` | `src/scope.rs` | Route, endpoint, and component include/exclude matching |
| `session` | `auth.rs`, `storage_state.rs`, `health.rs`, `persistence.rs`, `providers.rs`, `cookies.rs`, `secrets.rs` | Guarded authentication flows, private cookie/storage capture & restore across tabs, session expiry checks |
| `types` | `dom.rs`, `api.rs`, `bugs.rs`, `classifier.rs`, `graph.rs` | Shared serializable domain types |
| `url_origin` | `src/url_origin.rs` | Same-origin and localhost-alias (`localhost`, `127.0.0.1`, `0.0.0.0`, `::1`) equivalence |

`src/main.rs` wires `FrontCommand` plus two hidden internal subcommands (`scan`, `resume`) used solely by `src/front/map.rs` for per-role process isolation.

## Key Subsystems

### 1. Multi-Role Process Isolation & Resumability

`src/front/map.rs` reads `.brokenapp/config.toml`, enforces locality and `protected = false`, optionally launches `dev_cmd` in its own process group (`process.rs`), warms seeded routes with available role credentials (`warmup.rs`), and spawns one isolated scan subprocess per role (anonymous plus every configured `[[roles]]` entry).

- **Role isolation:** Each role writes to `.brokenapp/scans/<ts>/roles/<role>/`, produces its own inventory under `.brokenapp/history/roles/<role>/`, and renders `.brokenapp/map/roles/<role>/`. A role that fails login or expires is skipped (exit code `3`, `status: partial`) without losing already-mapped roles; its stale map is excluded from the freshly built `ROLE-ACCESS.md`.
- **Standard vs. full mode:** Standard mode defaults to 10 minutes and 80 views for fast iteration. `--full` removes global time/view caps (optional `max_hours` ceiling), raises per-view budgets, restarts a crashed managed dev server, and emits periodic ETA progress to stderr and `map-progress.json`.
- **Checkpointing & `--resume`:** The engine checkpoints completed crawl state at a cadence capped at 60 seconds and on `SIGINT`/`SIGTERM`. In-flight visits are requeued on resume. `map --resume` preserves completed roles and resumes the interrupted role if target/codebase/auth identity still matches.

### 2. Incremental Impact Analysis (`map --changed`)

`src/front/changed.rs` detects changed files via git (or modification times when git is absent). `src/front/impact.rs` maps those files to affected routes via route-defining files, layout/shell ancestry, transitive module imports, mapped `source` sites, and API endpoints.

- Zero UI routes affected → exits `0` without launching Chrome (`unmapped_files` explains why).
- App-wide files (framework config, middleware, root layout/entry, global styles, ≥60% of routes, or unattributed source/style edits) → conservatively falls back to a full crawl.
- Otherwise → crawls only the affected routes and merges them byte-for-byte into the previous inventory (`src/inventory/merge.rs`), preventing false `REMOVED` noise on uncrawled routes.

### 3. Mechanical Write Guard & Secret Boundary

- **Write guard:** `src/network/interceptor.rs` attaches CDP Fetch interception before navigation (scoped on local scans to write-capable resource types `Document`, `Xhr`, `Fetch`, `EventSource`, `Ping`, `Other` so static JS/CSS/font/image chunks load natively without pausing, and skipping `GetResponseBody` on static assets) and consults `crate::safety::write_guard_verdict`. Non-`GET`/`HEAD`/`OPTIONS` HTTP requests, GraphQL mutations, beacons, and form POSTs are recorded and either failed (`block`, default) or answered synthetically (`stub`). In addition, page instrumentation (`src/browser/cdp_helpers.rs`) wraps `WebSocket.prototype.send` to guard structured mutating WebSocket RPC/GraphQL/command frames before they hit the wire while letting read/subscribe/heartbeat frames pass, paired with CDP `Network.webSocketFrame*` observation for activity attribution and RPC error detection. Narrow exceptions apply only to same-origin form-login auth POSTs (`AuthWriteScope`) and explicit `[scan] write_guard_allow` rules (including `WS` patterns). Auth-page traffic is omitted from artifacts, and app-wrapped `console.error` calls or generic fetch-abort toasts caused solely by a write-guard block are suppressed from `Broken`.
- **Explicit non-goals of the guard:** unrecognized GET-based writes, Service Worker requests, and binary or opaque/unstructured WebSocket frames remain outside the guard; interactive `brokenapp login` capture opens an unguarded browser strictly for user sign-in.
- **Secret isolation & log privacy:** Literal secrets in `.brokenapp/config.toml` are rejected at load time. Role values come from `env:NAME` references or mode-600 gitignored `.brokenapp/credentials.toml`, enter scan subprocesses strictly through environment variables, and pass through `Redactor` (`src/front/roles.rs`, `src/front/secrets.rs`) before any stdout/stderr/JSON/log output. Raw API response bodies are omitted from `network.jsonl` by default (`output.include_response_bodies = false`), and any retained snippets or schema samples are scrubbed of sensitive keys, JWTs, API keys, Bearer tokens, cookies, and URL credentials before serialization.

### 4. Inventory, Stable Identity, Diff & Parity

- **Identity (`src/inventory/identity.rs`):** Controls are keyed by `<route>|<role>|<locator>[#n]` (`testid=` > non-generated `id=` > `aria=`/`name=` > normalized `text=` with `@header`/`@nav`/`@footer`/`@aside`/`@dialog` landmarks > `href=`). Digits/dates fold to `#` so live counters and timestamps don't churn diffs. A link's `href` is recorded as an *outcome* so retargeting shows up as `REWIRED`, not `REMOVED` + `ADDED`. Browser-generated error documents (`chrome-error://chromewebdata`, `about:neterror`, `#reload-button`) are excluded from route/control discovery.
- **Portable committed maps:** Each map directory writes a sanitized `ui-inventory.json` (local `scan_dir` cleared) alongside the Markdown/TSV/HTML renders so `ui`, `dead`, `journey`, and `parity` work on fresh clones without `.brokenapp/history/`.
- **Behavioral + RBAC Diff (`changes`):** Compares inventories across roles (`NOW DEAD`, `NOW BROKEN`, `REWIRED`, `REMOVED`, `ADDED`, `FIXED`, plus multi-role `ACCESS GAINED` / `ACCESS LOST` and `ENDPOINT ACCESS GAINED` / `ENDPOINT ACCESS LOST`) with deterministic coverage caveats (`not_observed` vs true `REMOVED`) and fail-closed CI `--fail-on` exit gating (missing baselines, rebaselined schemes, missing roles, or `0` visited routes on either map return `INCONCLUSIVE`, exit `1`).
- **Cross-App Parity (`parity`):** Compares two saved map directories across routes, endpoints, controls, and role-access matrices for legacy-to-rewrite verification.

## Design Invariants

1. **Single binary, zero background services:** No database daemon, no Node/TypeScript runtime, no cloud backend.
2. **One browser engine:** All browser automation goes through `BrowserManager` / `PageClient` (`chromiumoxide`).
3. **Deterministic artifacts:** `BTreeMap` / `BTreeSet` everywhere serialized so git diffs of `.brokenapp/map/` reflect real app changes, not hash randomization.
4. **Coverage & attribution honesty:** `not_exercised` never counts as working; static or incomplete source owners stay explicitly labeled (`probable`, `guess`, `ambiguous`, or unknown).
