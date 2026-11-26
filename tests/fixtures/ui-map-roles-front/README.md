# ui-map-roles-front

Fixture for `tests/integration/front_cli_test.rs` (roles, full mode, resume).
The app itself is served by a small HTTP server written in the test
(`RolesServer`); `app/` is its (empty) codebase, so seeds come from
`[scan] extra_routes`.

Pages:

| Route | anonymous | user | admin |
|---|---|---|---|
| `/` | yes | yes (+ Dashboard link) | yes (+ Dashboard and Admin links) |
| `/login` | login form | redirects to `/dashboard` | redirects to `/dashboard` |
| `/dashboard` | redirects to `/login` | yes | yes, plus a "Delete member" button |
| `/reports` | 404 | yes | yes |
| `/admin` | redirects to `/login` | redirects to `/login` | yes |
| `/admin/users` | redirects to `/login` | 403 | yes |
| `/logout` | never visited by the crawler (sign-out) | | |

`POST /login` accepts the throwaway users in `users.json` (they exist only in
this fixture server) and answers a wrong password with the login form again
("Invalid email or password").
