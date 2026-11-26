# Explorer Module — Scan Engine

## When to Read

Understanding or modifying the crawl/interaction pipeline.

## Data Flow

```
URL queue → engine.rs (main loop) → scheduler.rs (priority)
  → DOM discovery → interaction.rs (click/type)
  → snapshot.rs (capture) → bug detection
  → state_machine.rs (transitions) → coverage.rs (tracking)
```

## Parallel tabs

`scan.max_concurrent_tabs` (1-8, default 1; `BROKENAPP_MAX_CONCURRENT_TABS`
overrides it) runs that many page workers in one browser. `engine.rs`
(`Crawl`) holds the shared `RuntimeState` behind a `std::sync::Mutex` that is
only locked for synchronous sections (`assert_send` makes holding it across an
`.await` a compile error); the session and incremental saves sit behind tokio
mutexes. Workers pop from the shared scheduler; stop conditions, view ids
(`RuntimeState::allocate_view_id`), view identity (`visited_fingerprints`,
`ctl.active_views`: one tab per view), template sampling (`TemplateSampler`
reservations) and the scan-wide exercised-controls memory (claimed with
`claim_control` right before a click) are all decided under that lock.
Visits whose control-identity scope (route template, else route) is busy on
another tab wait (`ScanScheduler::pop_next_matching`): sibling instances of a
template run one after the other, as in a sequential crawl, so stateful
widgets are not split across instances; other routes run in parallel.

Each tab gets its own page (a window of its own when tabs > 1), write guard
(`NetworkInterceptor::attach_isolated`, Fetch on before the first navigation)
and attribution state keyed by `browser::TabKey` (CDP target id): current
action, action ids, document epochs, recent-action fallback and native
dialogs in the interceptor, console windows in `BugDetector`.

## Long runs

- **Budgets.** `max_duration_minutes = 0` / `max_views = 0` mean no cap. The
  stagnation and convergence stops wait while a queued URL belongs to a route
  no view was explored for (`RuntimeState::unvisited_route_pending`).
  `scan.view_budget_seconds > 0` replaces the automatic per-view watchdog.
- **Checkpoints.** `Crawl::checkpoint_ticker` saves every
  `checkpoint_interval_seconds` (at most 60 s; only one save runs at a time).
  Saves are light: checkpoint, `spec.json`, `bugs.json`, `coverage-gaps.json`,
  `scan-status.json` (`running`), and `scan-run.json`. Derived reports are
  written once at the end. Visits in flight (`LoopControl::in_flight_visits`)
  are left out of checkpoints: their URLs are requeued first and their partial
  view state is dropped. Hash maps are hashed canonically, so another process
  can verify the checkpoint. Template samples commit only after a visit
  finishes, so interrupted instances remain eligible after resume.
- **Stopping now.** `Crawl::stop_now` (session expired, browser gone) cancels the
  visits in flight. A cancelled `VisitSlot` withdraws its visit: the URL goes
  back to the front of the queue, the view id is retired, and its
  `interactions.jsonl` rows are dropped at finalization. SIGINT/SIGTERM
  (`interrupt.rs`, CLI only) drops the whole crawl future, with the same
  effect.
- **Resume** restores crawl memory (`CrawlResumeState`: crawl seconds, seeded
  routes, exercised controls, template instances, session log), compacts
  `interactions.jsonl` to the checkpoint's views, and logs in again (form
  roles) or reloads the saved session (`storage_state`).
- **Sessions.** `Crawl::recover_session` is serialized on the session lock and
  versioned by `SessionCtl::generation`. A tab that lands on the login page (or
  a burst of 401/403, or a failed canary) runs the session canary: a protected
  probe, else the page the login landed on. If the session is alive, the gate
  belongs to the role. If it ended, a renewable role logs in once and the tab
  retries; other tabs see the new generation and just retry. A saved or manual
  session stops the crawl with `session_expired`. Views that overlapped a
  re-login are explored again once under a new id.
- **Memory.** Error traffic is drained from the interceptor
  (`take_error_traffic`). The network and interaction logs are streamed to
  disk. `scan-run.json` reports peak RSS.

## Files

| File | Purpose |
|------|---------|
| `engine.rs` | Main scan loop, view processing, orchestration |
| `scheduler.rs` | URL priority queue, novelty scoring, depth limits |
| `interaction.rs` | Interaction pass: click buttons, fill forms, detect dead buttons |
| `state_machine.rs` | View transition tracking, state graph |
| `coverage.rs` | Template coverage, interaction coverage metrics |
| `cycle_detection.rs` | Detect infinite crawl loops |
| `form_mapping.rs` | Map form submissions to API mutations |
| `priority.rs` | Element interaction priority scoring |
| `template_sampler.rs` | Cap similar-template views |
| `url_utils.rs` | URL comparison, query param diffing |
| `run_report.rs` | `scan-run.json`: status, stop reason, budgets, session events, peak RSS |
| `interrupt.rs` | SIGINT/SIGTERM: checkpoint and stop (`interrupted`), resumable |
| `mod.rs` | Module entry, re-exports |

## Key Types

| Type | File | Description |
|------|------|-------------|
| `ScoredUrl` | scheduler.rs | URL wrapper for priority heap ordering |
| `ExplorationStrategy` | scheduler.rs | Strategy configuration |
| `PendingTransition` | engine.rs | Queued state transition |
| `ScanCheckpoint` | engine.rs | Progress persistence |

## Key Integration Points

- Creates bugs via: `bugs::BugDetector` (dead buttons, broken links)
- Reads config from: `config::BrokenAppConfig`
- Uses browser via: `browser::PageClient`
- Captures traffic via: `network::NetworkInterceptor`
- Classifies views via: `dom::classifier`
- Filters scope via: `scope::ScopeFilter`
- Manages sessions via: `session::SessionManager`
