# CI PR Gate Guide

Use `brokenapp map` and `brokenapp changes --fail-on` in CI to block pull requests that break controls, silently rewire flows, or leak access across login roles.

A ready-to-copy GitHub Actions workflow lives at [`examples/github-actions/pr-gate.yml`](../examples/github-actions/pr-gate.yml).

## How the Gate Works

1. **Baseline exists:** Your repository commits `.brokenapp/config.toml` (and `.brokenapp/map/`), and CI caches or stores `.brokenapp/history/` from `main` (or compares two saved map directories directly with [`brokenapp parity`](parity.md)).
2. **PR crawl runs safely:** CI boots the PR build locally and runs `brokenapp map --no-start` (or omits `--no-start` to let BrokenApp launch `project.dev_cmd`). The write guard blocks non-GET writes by default so the crawl never mutates a seeded CI database.
   - Use default **`standard` mode** (10m / 80 views) for PR gates, `--quick` (3m / 25 views) for lightweight smoke gates, or opt-in **`--full`** (optionally bounded by `[scan] max_hours` / `--depth`) on scheduled nightly audits.
   - If you run `brokenapp map --changed --json` in CI, inspect `changed.mode` first: when no UI routes are affected (`changed.mode == "skipped"`), no new snapshot is written. App-wide changes automatically fall back to a **whole-app scan (with your selected budget)** — not uncapped `--full` mode.
3. **Behavioral + RBAC diff gates the PR:**

```bash
brokenapp changes \
  --role all \
  --fail-on dead,broken,access-gained \
  --format markdown > brokenapp-changes.md
```

- Exits **`0`** when a valid baseline exists, both maps visited at least one route, and no selected violation category occurred.
- Exits **`1`** when one or more matching regressions or access drifts occurred, **or** when the baseline map is missing, rebaselined, or either map visited `0` routes (`INCONCLUSIVE` — never falsely passes!).

## `--fail-on` Policy Reference

Pass a comma-separated list to `--fail-on`:

| Token | Fails When | Typical Use |
|---|---|---|
| `dead` | Any previously working control becomes `NOW DEAD` | Recommended on every PR |
| `broken` | Any control becomes `NOW BROKEN` (JS error, HTTP ≥400, broken link) | Recommended on every PR |
| `no-effect` | A previously working control becomes `no_effect` (handler exists, no visible effect) | Opt-in for strict interaction checks (not included in `any`) |
| `access-gained` | A role newly reaches a route or control it previously could not (`ACCESS GAINED`) | Recommended for multi-role apps to catch RBAC leaks |
| `access-lost` | A role loses access to a previously reachable route or control (`ACCESS LOST`) | Enable for apps with stable role contracts |
| `rewired` | An existing control changes its navigation target or API endpoint (`REWIRED`) | Enable for strict checkout/billing/auth flows |
| `removed` | A previously observed control disappears on a route visited in both maps (`REMOVED`) | Enable on stable surfaces where removals require explicit review |
| `route-removed` | A previously mapped route disappears | Enable for stable route inventories |
| `endpoint-removed` | A previously observed endpoint is no longer called | Enable for stable API integration checks |
| `any` | Any behavioral or role-access regression above except `no-effect` | Strictest lock-down mode |

### Recommended Starter Policy

Start with high-signal, low-noise categories and tighten over time:

```bash
brokenapp changes --role all --fail-on dead,broken,access-gained --format markdown
```

## Output Formats & Machine-Readable Contracts

- `--format text` — Compact terminal output (default).
- `--format md` / `--format markdown` — GitHub-flavored Markdown summary ideal for sticky PR comments.
- `--format json` (or `--json`) — Structured payload for custom dashboards, Slack alerts, or policy engines.
- **Uniform JSON error envelope:** On command failure, all `--json`, `--compact`, and `--format json` commands write `{ "exit_code": 1, "status": "error", "error": "..." }` to stdout (plus the error to stderr), so CI scripts can parse failures reliably.
- **`map --json` completion metadata:** Exposes `stop_reason`, `queue_remaining`, `resolved_limits`, and actionable `next` commands per run (plus `stop_reason` and `queue_remaining` per role). In nightly `--full` workflows, check `queue_remaining > 0` to detect budget-stopped runs that can continue with `brokenapp map --resume`.

You can also compare two explicit inventory files without relying on `.brokenapp/history/`:

```bash
brokenapp changes --between baseline.inventory.json pr.inventory.json \
  --fail-on dead,broken --format markdown
```

- Missing or rebaselined baselines with `--fail-on` return `INCONCLUSIVE` (exit `1`) rather than falsely passing.
- Background polling loops and session-renewal heartbeats (e.g. periodic `setInterval` GETs or `POST /api/session/renew`) are automatically excluded from per-control attribution so consecutive CI runs do not flake with false `REWIRED` or `ENDPOINT REMOVED` failures.

## Running Chrome in Linux CI

Set these environment variables so headless Chromium runs reliably inside GitHub-hosted runners and sandboxed containers:

```bash
export BROKENAPP_CHROME_EXECUTABLE="/path/to/chrome"  # or BROKENAPP_CHROME
export BROKENAPP_NO_SANDBOX=1
export BROKENAPP_CHROME_ARGS="--disable-dev-shm-usage"
export BROKENAPP_HOME="/tmp/brokenapp-home"           # optional: when ~/.brokenapp is read-only
```

Verify detection (and catch unrecognized `config.toml` keys early) before crawling, and verify role readiness with `brokenapp login --role <name> --json` (which honors `ready_timeout_secs` and retries cold SSR compiles once):

```bash
brokenapp doctor
```

## Handling Role Credentials Safely in CI

Declare roles with `env:` references in `.brokenapp/config.toml`:

```toml
[[roles]]
name = "admin"
method = "form"
login_url = "/sign-in"
username = "env:ADMIN_EMAIL"
password = "env:ADMIN_PASSWORD"
check = "/api/me"

[[roles]]
name = "member"
method = "form"
login_url = "/sign-in"
username = "env:MEMBER_EMAIL"
password = "env:MEMBER_PASSWORD"
check = "/api/me"
```

Pass the values via GitHub Actions Secrets only to the `brokenapp map` step:

```yaml
- name: Crawl app (write-guarded)
  env:
    ADMIN_EMAIL: ${{ secrets.BROKENAPP_ADMIN_EMAIL }}
    ADMIN_PASSWORD: ${{ secrets.BROKENAPP_ADMIN_PASSWORD }}
    MEMBER_EMAIL: ${{ secrets.BROKENAPP_MEMBER_EMAIL }}
    MEMBER_PASSWORD: ${{ secrets.BROKENAPP_MEMBER_PASSWORD }}
  run: brokenapp map --no-start
```

- Always use throwaway CI seed accounts on ephemeral CI data.
- Never commit `.brokenapp/credentials.toml` or `.brokenapp/session/*`.
- If a role fails login in CI, `brokenapp map` exits `3` (`status: partial`); treat exit `3` as a failed CI setup so stale role coverage never silently passes.

## Seeding Baseline History on `main`

To keep `.brokenapp/history/` warm across PRs, add a small `push` workflow on `main` that runs `brokenapp map --no-start` and saves `.brokenapp/history` with `actions/cache/save@v4` (keyed by `brokenapp-history-main-${{ github.sha }}`). Pull requests restore the latest `brokenapp-history-main-` cache before running `brokenapp map` and `brokenapp changes`.

Because `brokenapp changes --fail-on` returns `INCONCLUSIVE` (exit `1`) whenever a baseline is missing or rebaselined, missing caches or first-time setups will fail loudly instead of green-lighting unverified PRs. Alternatively, if you map both the base commit and PR commit in one workflow (or compare two environments), use [`brokenapp parity`](parity.md).
