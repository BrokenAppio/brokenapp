<!-- brokenapp:start -->
## UI Map (BrokenApp)

This repo keeps a write-guarded behavioral map in `.brokenapp/map/` (anonymous map, per-role maps in `roles/<role>/`, cross-role access in `ROLE-ACCESS.md`).

- **Preflight & monorepos:**
  - `brokenapp doctor --json` — check `ok`, `protected`, `resumable_run`, and unknown config keys (never run `init --force` on an existing project; on monorepos target one app with `brokenapp init --codebase apps/<web-app>`; in sandboxes where `~/.brokenapp` is unwritable, set `BROKENAPP_HOME=/tmp/brokenapp-home`).
  - **Roles & login:** `brokenapp roles list --json`; add roles via `brokenapp roles add <role> --method form|session|cookie|bearer|supabase` (for Next.js `@supabase/ssr` with custom cookie names, prefer `form` or `session`). Verify any role first with `brokenapp login --role <name> --json` (honors `ready_timeout_secs` + cold-SSR retry; ask the user for interactive `session` login or missing env vars).
- **Read before editing (offline, no browser):**
  - Fresh clone (no local `history/`): `brokenapp ui`, `dead`, `journey`, and `parity` fall back to committed `.brokenapp/map/ui-inventory.json` (and `roles/<role>/ui-inventory.json`), or `grep` `ui-map.tsv`, `UI-MAP.md`, `endpoints.tsv`, and `ROLE-ACCESS.md` directly.
  - Query commands: `brokenapp ui --route /path --exact-route --compact` (check `requested_state_observed`; add `--role <name|all>`), `brokenapp dead --role all`, and `brokenapp journey "<route | METHOD /path | label:Text>" --role <r>` (traces route hops + in-page modal/drawer/tab/wizard chains; default `--max-hops 15`, raise for long flows).
  - After `map --route /x`: merges into the existing whole-app map by default; pass `--no-merge` for an isolated partial snapshot (then read via `--inventory <path>`).
- **Verify after UI edits (before saying done):**
  - Run `brokenapp map --changed --json`; inspect top-level `mode`, per-role `status`, `stop_reason`, and `queue_remaining` first (top-level `"mode": "skipped"` writes no new snapshot; app-wide edits fall back to a whole-app scan with your selected budget; `--max-minutes` applies **per role**; pass `--tabs 1` if the dev server stalls).
  - Run `brokenapp changes --role all` (missing/rebaselined baseline with `--fail-on` returns `INCONCLUSIVE`, exit `1`) and fix/explain unexpected `NOW DEAD`, `NOW BROKEN`, `REWIRED`, `REMOVED`, `ACCESS GAINED`, or `ACCESS LOST`.
- **Opt-in deep SPA audits (never default):**
  - Run `brokenapp map --full` (add `--depth 6..10` for deep wizards/modals, `--max-interactions`, `--view-budget`) only when asked for giant SPAs, 100%-button/route audits, or deep customer journeys; resume interrupts or `queue_remaining > 0` stops with `brokenapp map --resume`.
- **Exit codes & JSON:** `0` ok/no-op · `1` error/gate fail/`INCONCLUSIVE`/unmatched journey · `3` partial role failure (incl. `timed_out_empty`, preserving prior good map) · `130` interrupted (`--resume`). CLI/invocation errors emit `{ "exit_code": 1, "status": "error", "error": "..." }` on stdout; domain exit-1 results (`journey` unmatched, `changes`/`parity --fail-on`) return their structured domain JSON.
- **Honest coverage:** Quote `exercised/exercisable` controls and `visited/known` routes; `not_exercised` != working; probed link != clicked execution; stitched journey != E2E replay.
- **Safety & secrets:**
  - Local targets only; never enable `allow_remote`, remove `protected = true`, or pass `--allow-writes` without disposable-data confirmation.
  - Never ask for, read, print, or commit `.brokenapp/credentials.toml` or `.brokenapp/session/*`.
  - Commit `.brokenapp/config.toml` and `.brokenapp/map/` only; everything else in `.brokenapp/` is gitignored and sensitive.
- **Opt-in feedback:** Only if the user opted in (`brokenapp feedback --opt-in` / `BROKENAPP_FEEDBACK_OPT_IN=1`) or explicitly asks, submit sanitized CLI bug/UX reports via `brokenapp feedback "<summary>" --category bug|ux|auth|crawler|rbac --agent <name> --include-stats --send` (preview with `--dry-run`).
<!-- brokenapp:end -->
