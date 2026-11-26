# Cross-App Parity (`brokenapp parity`)

When rewriting a legacy monolith, migrating frameworks (e.g., Rails → Next.js, AngularJS → React), or rebuilding a frontend with AI coding agents, regressions rarely announce themselves as compiler errors. Instead, routes quietly vanish, buttons stop calling the right API, or an admin-only screen becomes reachable by regular members.

`brokenapp parity <baseline> <candidate>` compares two saved BrokenApp maps across every matching login role and produces a behavioral + RBAC parity report.

## 3-Step Rewrite Parity Workflow

### 1. Map the Baseline (Legacy) App

```bash
cd legacy-app
brokenapp init --url http://127.0.0.1:3000 --dev-cmd "bundle exec rails server"
brokenapp roles add admin --login-url /login
brokenapp roles add member --login-url /login
brokenapp map --full   # or standard `brokenapp map` for smaller apps
```

This writes the baseline maps — including sanitized portable `ui-inventory.json` files — into `legacy-app/.brokenapp/map/` (and timestamped history in `legacy-app/.brokenapp/history/`), so `brokenapp parity` works directly on committed `.brokenapp/map/` directories even on a fresh clone without `.brokenapp/history/`.

### 2. Map the Candidate (Rewrite) App

Use the same role names (`admin`, `member`, etc.) so `parity` pairs each role automatically:

```bash
cd new-app
brokenapp init --url http://127.0.0.1:3001 --dev-cmd "npm run dev"
brokenapp roles add admin --login-url /sign-in
brokenapp roles add member --login-url /sign-in
brokenapp map --full
```

### 3. Run the Parity Check

```bash
brokenapp parity ../legacy-app/.brokenapp/map ./.brokenapp/map \
  --format markdown \
  --fail-on dead,broken,access-gained,removed
```

## What `parity` Reports

| Section | What It Catches |
|---|---|
| **Missing routes** | Pages visited in the baseline that are absent or unreachable in the candidate |
| **Missing endpoints** | Backend endpoints (`GET/POST/PUT/DELETE ...`) observed in baseline interactions or page loads that the candidate no longer calls |
| **Missing or regressed controls** | Controls present in baseline that disappeared (`REMOVED`), stopped working (`NOW DEAD`, `NOW BROKEN`), or changed target/endpoint (`REWIRED`) |
| **Role-access drift** | Multi-role permission regressions between baseline and candidate: `ACCESS GAINED` (possible privilege leak) and `ACCESS LOST` (broken feature for an entitled role) |
| **Coverage comparison** | Side-by-side exercised/exercisable controls and visited/known routes for both maps so low coverage is never mistaken for parity |

## Output Formats & CI Gating

```bash
# Human-readable terminal summary (default)
brokenapp parity ./baseline-map ./candidate-map

# Markdown report for PR comments or migration sign-off docs
brokenapp parity ./baseline-map ./candidate-map --format markdown > parity-report.md

# Machine-readable JSON for dashboards or custom assertions
brokenapp parity ./baseline-map ./candidate-map --json > parity.json

# Fail CI (exit 1) on behavioral regressions or privilege leaks
brokenapp parity ./baseline-map ./candidate-map \
  --fail-on dead,broken,access-gained,access-lost,removed
```

## Reading Parity Results Honestly

- **Coverage matters on both sides:** If the baseline visited 40 routes and the candidate only visited 18 because of a timeout or missing login, fix the candidate's crawl coverage before trusting a clean diff.
- **Intentional renames show up cleanly:** Renamed paths or intentionally replaced endpoints appear explicitly in the missing-routes / rewired sections so reviewers can sign off on each planned difference instead of guessing.
- **Dynamic records:** Seed both apps with comparable local fixture data (e.g., an active order, a draft invoice, an empty state) so route templates (`/orders/:id`) exercise the same controls on both sides.
- **Write guard applies to both maps:** Blocked writes (`calls POST /api/orders (blocked)`) verify identical client-to-API wiring without requiring either app to mutate real records.
- **Polling noise filtered automatically:** Periodic background polls and heartbeat keepalives (e.g. `setInterval` fetches or `POST /api/session/renew`) are excluded from per-control attribution so consecutive runs on identical code stay deterministic.
