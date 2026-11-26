# Bugs Module — Detection Pipeline

## When to Read

Adding new bug categories, modifying detection logic, adjusting severity/confidence.

## Architecture

`BugDetector` (detector.rs) is the central recorder. Specialized detectors feed it:

| Detector File | Bug Categories | Triggered By |
|---------------|---------------|--------------|
| `detector.rs` | All (central record methods) | Other detectors |
| `dead_buttons.rs` | DeadButton | explorer/interaction.rs |
| `broken_links.rs` | BrokenLink | explorer/engine.rs |
| `console_errors.rs` | ConsoleError | CDP event listener |
| `server_errors.rs` | ServerError | network/interceptor.rs |
| `accessibility.rs` | AccessibilityViolation | dom/discovery pass |
| `performance.rs` | PerformanceIssue, N+1 | network analysis |
| `form_fuzz_replay.rs` | SecurityObservation | form fuzzing pass |
| `form_validation.rs` | Form validation findings | form testing |
| `custom_rules.rs` | User-defined rules | config-driven |
| `mod.rs` | Module entry, re-exports | — |

## Key Methods on BugDetector

```
record_dead_button(url, view, selector, label, precondition, pattern, classification)
record_broken_link(url, status)
record_server_error(endpoint, status, body)
record_a11y_finding(...)
record_form_fuzz_finding(...)
bugs_snapshot() → Vec<Bug>
```

## Adding a New Bug Category

1. Add variant to `BugCategory` in `src/types/bugs.rs`
2. Create detector file in `src/bugs/` (e.g. `my_detector.rs`)
3. Add `record_*` method to `BugDetector` in `detector.rs`
4. Register module in `mod.rs`
5. Call from the appropriate pipeline stage (explorer, network, etc.)
