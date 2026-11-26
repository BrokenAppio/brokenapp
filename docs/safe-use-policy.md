# Safe Use & Security Policy

BrokenApp is a local-first behavioral mapping and verification tool for web applications you own or are explicitly authorized to test.

## Authorized Use Only

Only crawl applications you own or have explicit written authorization to test.

Prohibited use includes:

- Crawling third-party websites or production services without authorization
- Bypassing access controls, rate limits, or legal/contractual restrictions
- Running with `--allow-writes` against shared, staging, or production backends

## Local-First & Authorized Remote Compliance Enforcement

- **Local targets by default:** `brokenapp init` and `brokenapp map` accept only local addresses (`localhost`, `127.0.0.1`, `::1`, `0.0.0.0`, and `.local`/`.test`/`.localhost` local hostnames) unless `scan.allow_remote = true` is explicitly configured in `.brokenapp/config.toml`.
- **Protected repositories:** Setting `protected = true` under `[project]` (or running `brokenapp init --protected`) causes `brokenapp map` to refuse every scan. Use this on repositories connected to live user data.
- **Fail-closed host allowlist (`scan.allowed_hosts`):** Accepts exact hosts (`app.example.com`) and strict wildcard subdomains (`*.example.com`). Navigations, redirects, `XHR`/`Fetch`, `WebSocket` connections, `EventSource`, `Ping`, and any non-`GET`/`HEAD` requests outside the allowlist fail closed at the browser network/JS layer before packets leave Chromium (passive read-only `GET` static assets remain allowed so CDN-backed pages still render).
- **Scoped identifying headers & custom UA (`scan.extra_headers`, `scan.user_agent`):** Identifying headers (e.g. `X-QA-Runner`) are stamped at the CDP `Fetch` layer **only** on in-scope / `allowed_hosts` requests (never leaked to third-party CORS origins). `scan.user_agent` overrides Chromium's `User-Agent` via CDP `Emulation.setUserAgentOverride`.
- **Polite pacing & hard-abort circuit breakers:** `scan.interaction_delay_ms` and `scan.max_requests_per_second` cap UI and HTTP request rates; remote targets automatically skip parallel warm-up and anonymous link-probing bursts. `scan.abort_on_rate_limits` (default `5` HTTP 429 responses in 60s when `allow_remote = true`) and `scan.abort_on_antibot_challenges` (default `2` WAF/challenge pages when `allow_remote = true`) stop the crawl cleanly (`rate_limited` / `antibot_challenge`) and preserve the last good baseline map on disk.

## Mechanical Write Guard: Guarantees & Caveats

By default (`scan.write_guard = "block"`), BrokenApp attaches a Chrome DevTools Protocol (CDP) network interceptor to every crawl tab before navigation. On local scans, CDP `Fetch.enable` scopes interception to write-capable resource types (`Document`, `Xhr`, `Fetch`, `EventSource`, `Ping`, `Other`) so static JS/CSS/font/image assets load natively without pausing.

### What the Write Guard Stops

- All non-`GET`/`HEAD`/`OPTIONS` HTTP requests (`POST`, `PUT`, `PATCH`, `DELETE`)
- GraphQL mutations (HTTP and GraphQL-WS)
- `navigator.sendBeacon` requests
- HTML form `POST` submissions
- Structured mutating WebSocket frames (JSON-RPC, Effect-RPC, tRPC-WS, GraphQL-WS, Socket.IO, Phoenix, and command/mutation events via in-page `WebSocket.prototype.send` interception, while allowing reads, subscriptions, and heartbeats)

Intercepted writes are recorded in the scan log and attributed to the triggering control (e.g. `calls POST /api/orders (blocked)` or `calls WS /ws#server.updateSettings (blocked)`), then aborted (`block`) or answered with a synthetic client-side response (`stub`) before reaching your backend. App-wrapped `console.error` logs and generic network-abort toasts triggered solely by a write-guard block are suppressed from `DEAD-UI.md` `Broken` so real application failures remain clearly visible.

Only two narrow exceptions pass through:

1. Same-origin form-login authentication submissions during role sign-in (`AuthWriteScope` — e.g. NextAuth `/api/auth/callback/credentials`, Better Auth, or custom login POSTs; logout and non-auth writes stay blocked, and auth-page traffic is omitted from saved artifacts).
2. Explicit patterns you configure under `[scan] write_guard_allow` (for example `POST */api/graphql` to let GraphQL read queries execute while GraphQL mutations remain blocked, or `WS <url-glob>` / `WS <url-glob>#<op>` patterns).

### What the Write Guard Does NOT Stop (Honest Caveats)

- **Unrecognized GET-based writes:** If your application mutates state inside a `GET` handler whose URL does not match known write markers, the HTTP method guard will not classify it as a write. Exclude such paths via `exclude_routes`.
- **Service Worker traffic:** Requests handled or originated inside a Service Worker can bypass page-level CDP Fetch interception.
- **Binary or opaque background WebSocket protocols:** During an active UI interaction, unrecognized non-read text and binary WebSocket frames fail closed under the write guard unless allowlisted; however, background/unprompted binary or opaque custom-protocol frames sent outside an active interaction pass through unguarded so WS handshakes and read streams stay functional. Use `exclude_routes` or a disposable local backend for apps with unprompted binary WebSocket mutations.
- **Interactive session capture:** `brokenapp login --role <name>` (for `session` or `manual` roles) opens a normal, **unguarded** browser window so a human can complete SSO/MFA. Use that window strictly to sign in; subsequent `brokenapp map` runs execute guarded.

### `--allow-writes` Policy

Passing `--allow-writes` (or setting `scan.write_guard = "off"`) disables the write guard and sends live mutations to your backend. Use it **only** against disposable local databases you can reset, never against shared, staging, or production environments.

## Credentials & Sensitive Artifacts

- **Zero secrets in `config.toml`:** Literal passwords, tokens, or cookies in `.brokenapp/config.toml` are rejected at load time. `brokenapp init` also refuses or externalizes secret inline assignments from `--dev-cmd` into `[project.dev_env]` as `env:NAME` references.
- **Private local storage:** Role credentials live in shell environment variables (`env:NAME`) or `.brokenapp/credentials.toml`, created with permissions `0600` (`brokenapp map` refuses to read it if group/other permissions are open) and excluded via `.brokenapp/.gitignore`.
- **Environment-only injection & log redaction:** Credentials enter isolated role scan subprocesses strictly through environment variables and are redacted from stdout, stderr, logs, and `--json` output. Raw API response bodies are omitted from `network.jsonl` by default (`output.include_response_bodies = false`); when explicitly enabled, retained snippets and schema samples are scrubbed of sensitive fields, JWTs, API keys, Bearer tokens, cookies, and URL credentials before serialization.
- **Use throwaway test accounts:** Never configure real user or production administrator credentials.
- **Review committed maps like code:** Commit only `.brokenapp/config.toml` and `.brokenapp/map/`. Keep `.brokenapp/scans/`, `.brokenapp/history/`, `.brokenapp/session/`, and `.brokenapp/credentials.toml` gitignored. Even redacted maps contain route paths, control labels, endpoints, and source paths — review them before pushing to a public repository.

## Zero Silent Telemetry & Opt-In Feedback

BrokenApp never phones home during `init`, `roles`, `login`, `map`, `ui`, `dead`, `journey`, `changes`, `parity`, `doctor`, or `projects`.

- **Strictly opt-in:** `brokenapp feedback` transmits nothing unless `--send` is explicitly passed, and agent-initiated submissions (`--agent <name> --send`) fail closed (`opt_in_required`) unless you explicitly opt in via `brokenapp feedback --opt-in` (stored in `$BROKENAPP_HOME/settings.json`) or `BROKENAPP_FEEDBACK_OPT_IN=1`.
- **Inspect before sending:** Run with `--dry-run` (or omit `--send`) to inspect the exact locally scrubbed JSON payload on stdout with zero network activity.
- **Defense-in-depth scrubbing:** Secrets (JWTs, API keys, `Bearer` tokens, `Cookie:` headers, URL credentials) and local home paths are redacted locally before transmission. Optional `--include-stats` sends aggregate numeric counts across mapped roles and framework name only — never target URLs, routes, control labels, project names, or source code.
