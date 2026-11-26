---
name: brokenapp
description: Use before editing, debugging, or reviewing web UI; to inspect buttons, links, forms, modals, tabs, wizards, endpoints, dead/broken controls, multi-step journeys, or role access (admin, member, ...); or before calling a UI task done. Queries .brokenapp/map/ offline and refreshes it with `brokenapp map --changed`.
---

# BrokenApp UI Map

`.brokenapp/map/` holds a write-guarded behavioral map: anonymous map at root (`UI-MAP.md`, `ui-map.tsv`, `endpoints.tsv`, `DEAD-UI.md`, `CHANGELOG.md`, `UI-MAP.html`, `ui-inventory.json`), per-role maps in `roles/<role>/`, and cross-role access in `ROLE-ACCESS.md` / `role-access.tsv`.

## 1. Orient, Preflight & Login Roles
```bash
brokenapp doctor --json        # check `ok` and warnings (`protected`, `resumable_run`, unknown config keys)
brokenapp projects --json      # registered projects & latest maps
brokenapp roles list --json    # configured roles & readiness
```
- Never run `brokenapp init --force` on an existing project; run `brokenapp init` only if `.brokenapp/config.toml` is missing (`--agent claude-code|agents-md|all|none`). On monorepos, target one app: `brokenapp init --codebase apps/<web-app>`. In sandboxes where `~/.brokenapp` is unwritable, set `BROKENAPP_HOME=/tmp/brokenapp-home`.
- **Login roles** (`env:` references only; never touch credentials yourself — ask the human to export vars or run interactive login):
  - Form: `brokenapp roles add <role> --method form --login-url /login --username-env VAR --password-env VAR --check /dashboard`
  - Cookie / Bearer / Supabase: `--method cookie --cookie-env VAR --check /api/me` · `--method bearer --token-env VAR` · `--method supabase` (for Next.js `@supabase/ssr` with custom cookie names, prefer `form` or `session`).
  - Interactive SSO/MFA: `brokenapp roles add <role> --method session`, then ask the human to run `brokenapp login --role <role>`.
  - **Verify every role first** with `brokenapp login --role <role> --json` (honors `ready_timeout_secs` + cold-SSR retry) before `brokenapp map --role <role>`.

## 2. Read Saved Evidence (offline, no browser)
- **Fresh clone (no `.brokenapp/history/` yet):** `brokenapp ui`, `dead`, `journey`, and `parity` fall back to committed `.brokenapp/map/ui-inventory.json` (and `roles/<role>/ui-inventory.json`), or `grep` `ui-map.tsv`, `endpoints.tsv`, and `ROLE-ACCESS.md` directly.
- **Query commands:**
```bash
brokenapp ui --route /settings --exact-route --compact    # page scope + coverage (check `requested_state_observed`; add `--exclude-shell`)
brokenapp ui --role admin --text "Delete" --compact       # one role (`--role all` merges all roles)
brokenapp dead --role all                                 # broken / dead / no_effect + obscured top covers (`--include-unexercised` for gaps)
brokenapp journey "POST /api/orders" --role member        # traces route hops + in-page modal/drawer/tab/wizard chains
```
- `journey` accepts `<route | "METHOD /path" | label:Text>`, defaults to `--max-hops 15` (raise e.g. `--max-hops 40`), supports `--format text|md|markdown|json`, and reports steps (route vs. in-page), per-kind counts, endpoints, broken/unexercised flags, and `path_evidence`.
- **After `map --route /x`:** merges into the existing whole-app map by default; pass `--no-merge` for an isolated partial snapshot (then read via `--inventory <path>`).
- **JSON exit-1 contract:** CLI errors emit `{ "exit_code": 1, "status": "error", "error": "..." }` on stdout (+ stderr); domain exit-1 results (`journey` unmatched, `changes`/`parity --fail-on` fail or `INCONCLUSIVE`) return structured domain JSON.

## 3. Pick the Right `map` Mode
| Command | Budget & Behavior | When to Use |
|---|---|---|
| `brokenapp map --changed` | Re-crawls affected routes & merges; skips if no UI affected; falls back to whole-app scan (with your budget) on app-wide edits | **Default after edits** |
| `brokenapp map --quick` | 3m / 25 views | Fast smoke check |
| `brokenapp map --route /x` | Re-crawls `/x` & merges into existing map (add `--no-merge` for an isolated snapshot read via `--inventory <path>`) | Single-route debug/verify |
| `brokenapp map` | Standard baseline: 10m / 80 views, depth 2, 25 controls/view | Initial map / routine refresh |
| `brokenapp map --full` | **Opt-in only** (`--mode full`): uncapped time/views, convergence off, depth 4, 1000 controls/view, `view_budget_seconds=300`, `extra_routes` pinned, 15s nested floor | Giant SPAs, 100%-control audits, deep journeys (**only when asked**) |

- `--max-minutes` applies **per role**. Pass `--tabs 1` if a dev server stalls; pass `--view-budget 600` on dense single-route tabbed SPAs; for deep wizards under `--full`, add `--depth 6..10`, `--max-interactions <1-1000>`, `extra_routes`, or `[scan.test_data]`.
- Monitor `.brokenapp/scans/<ts>/map-progress.json`; continue interrupted or `queue_remaining > 0` runs with `brokenapp map --resume`.

## 4. Verify & Gate
```bash
brokenapp map --changed --json            # check top-level `mode`, per-role `status`, `stop_reason`, `queue_remaining`, `next`
brokenapp changes --role all              # behavioral + RBAC diff (`--between OLD NEW`, `--fail-on ...`)
brokenapp parity <baseline> <candidate>   # compare a legacy app against a rewrite
```
- Check `map --changed --json` **before** `changes`: `"mode": "skipped"` writes no new snapshot. Fix or explain unexpected `NOW DEAD`, `NOW BROKEN`, `REWIRED`, `REMOVED`, `ACCESS GAINED`, or `ACCESS LOST`. Missing/rebaselined baselines with `--fail-on` return `INCONCLUSIVE` (exit `1`).

## 5. Exit Codes, Honest Coverage, Safety & Opt-In Feedback
- **Exit codes:** `0` ok/no-op · `1` error, gate fail, `INCONCLUSIVE`, or unmatched journey · `3` partial role failure (incl. `timed_out_empty`, preserving prior good map) · `130` interrupted (`--resume`).
- **Statuses & coverage:** Always quote `exercised/exercisable` controls and `visited/known` routes.
  - `ok`: exercised with observable effect (confirm it is the *intended* effect). `dead`: no effect and no handler found.
  - `no_effect`: handler exists, no visible effect — **read the handler first**. `broken`: error, HTTP ≥400, broken link, or repeated timeout.
  - `not_exercised`: **never evidence it works** (inspect `obscured` top covers). Probed link != clicked execution. `calls POST /x (blocked)`: client wiring observed; server aftermath unobserved.
  - `journey` `stitched_candidate` != E2E replay; verify `probable`/`guess`/`static` `file:line` in source before editing.
- **Safety & secrets:** Local targets only — never set `scan.allow_remote = true`, remove `protected = true`, or pass `--allow-writes` without disposable-data confirmation. Write guard stays `block` (blocks HTTP writes & structured mutating WebSocket frames; state-changing GETs, Service Workers, and background opaque WS frames remain outside it). Never ask for, read, print, or commit `.brokenapp/credentials.toml` or `.brokenapp/session/*`. Commit `.brokenapp/config.toml` and `.brokenapp/map/` only.
- **Opt-in agent feedback:** Only if opted in (`brokenapp feedback --opt-in` or `BROKENAPP_FEEDBACK_OPT_IN=1`) or explicitly asked, run `brokenapp feedback "<summary>" --category bug|ux|auth|crawler|rbac|journey --agent <name> --include-stats --send` (omitting `--send` or passing `--dry-run` always previews locally without sending).
