# ui-map-roles fixture

A small multi-role app with cookie sessions, served in-process by
`tests/integration/long_run_roles_test.rs` on a port in 47280-47289. It
exercises long, multi-tab, authenticated crawls: form login per role, saved
browser sessions (`[auth] type = "storage_state"`), session expiry mid-scan,
role-gated routes, and interrupt/resume.

Throwaway credentials (only valid against this fixture server):

| Role  | Email                    | Password               |
|-------|--------------------------|------------------------|
| user  | user@roles.fixture.test  | fixture-user-pass-1    |
| admin | admin@roles.fixture.test | fixture-admin-pass-2   |

Tests pass them to the scan only through its environment
(`ROLES_FIXTURE_<ROLE>_EMAIL` / `_PASSWORD`, referenced as `env:` in the scan
config) and assert they never appear in any scan output.

Routes:

- Public: `/` (landing), `/login`, `/docs/<name>` (a chain of public pages).
- `GET /login?auto=<role>` signs in from the page itself (a `fetch` POST to
  `/login`, then local/session storage tokens), then goes to `/dashboard`:
  the session-capture test needs no human.
- `POST /login` (form fields `email`, `password`) sets the `sid` cookie
  (HttpOnly) and redirects to `/dashboard`.
- Protected (no session: `302 /login?next=...`): `/dashboard`, `/reports`,
  `/reports/weekly`, `/reports/monthly`, `/profile`, `/settings`.
- Admin only (a user session: `302 /login?reason=forbidden`): `/admin`,
  `/admin/users`, `/admin/audit`.
- `GET /logout` ends the session. It is linked from every protected page and
  must never be requested by a scan.
- `GET /api/me`, `/api/stats`, `/api/reports`: JSON, `401` without a session.
  Writes (`POST /api/...`) must never reach the server (write guard).

Every protected page has a `Storage ok` button when the saved session's
storage is present in the tab (`localStorage.fixture_ui_token = ui-<role>`,
`sessionStorage.fixture_tab_token = tab-<role>`), else `Storage missing`.

The server can expire every session once, after a given number of
authenticated page loads (mid-scan session expiry).

The hostile-auth regression changes the login fields to `account` and
`credential`, returns a response containing a fixture access token and echoed
credentials, and attempts a background autosave on the authenticated landing
page. The login must succeed, the autosave must remain blocked, and no
credential or access-token bytes may appear in scan artifacts.
