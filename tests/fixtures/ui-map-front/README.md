Route-discovery source tree for `tests/integration/front_cli_test.rs`.
The pages are served by the test's own HTTP server; Astro is never run.
`404.astro` must not become a route or seed, `logout.astro` must not be
seeded, and `towns/[slug].astro` must reach the scan as a route template.
