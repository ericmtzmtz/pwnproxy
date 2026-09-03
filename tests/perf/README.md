# Performance baseline

`baseline.json` is a versioned reference for the crawler's crawl performance,
used by the CI `perf-check` job (`pytest tests/perf -m "perf and not live"
--perf-check`). A regression fails when duration exceeds 3x the baseline or
fewer than 90% of the baseline pages are fetched.

## Current reference

| Field | Value |
|---|---|
| duration_ms | 281.9 |
| max_rss_kb | null (best-effort; only captured on Linux) |
| pages_fetched | 19 |
| errors | 0 |

**Environment:** local Windows dev box (2026-09-03, commit not recorded here).
`max_rss_kb` is `null` on Windows — this is an **interim** reference used only
to validate the tooling.

## Regenerating the canonical baseline

The canonical baseline MUST be recorded on a **Linux GitHub Actions runner**
(the same image `perf-check` runs against), where `max_rss_kb` is captured:

1. Trigger the manual `perf-record` job in `.github/workflows/ci.yml`
   (`workflow_dispatch`). It records the baseline on the runner and uploads
   `baseline.json` as an artifact.
2. Download the artifact, commit `baseline.json` together with this note
   updated with: runner image, date, commit SHA, tolerance ×3.

Local regeneration on Windows records `duration_ms`/`pages_fetched` only
(`max_rss_kb: null`) — acceptable for a quick sanity check, not for the
canonical reference.

## Tolerance

`TOLERANCE = 3.0` (duration) and `pages >= 90%` in `test_perf_baseline.py`.
