# CI, performance baseline and flaky-test policy

This project runs CI on GitHub Actions (`.github/workflows/ci.yml`). Python
target is `^3.12`; every job installs deps with `poetry install`.

## Jobs

| Job | When | Command |
|---|---|---|
| `suite` | push / PR to main | `pytest -m "not live and not golden and not perf"` |
| `goldens` | push / PR to main | `pytest -m "golden and not live"` |
| `perf-check` | push / PR to main | `pytest tests/perf -m "perf and not live" --perf-check` |
| `flaky-check` | manual (`workflow_dispatch`, `run_flaky_check`) | suite `pytest -m "not live" --maxfail=1` × 3 |
| `perf-record` | manual (`workflow_dispatch`, `run_perf_record`) | records baseline on the Linux runner, uploads artifact |

Each job passes its own explicit `-m` filter. Pytest uses the LAST value of the
option, so the job's CLI `-m` overrides the local `addopts = "-m 'not live'"`
in `pyproject.toml` — CI never depends on the local addopts for filtering.

## Performance baseline

`tests/perf/baseline.json` is the versioned reference for crawl performance
(duration, pages fetched, best-effort RSS on Linux). The `perf-check` job fails
if duration exceeds 3x the baseline or fewer than 90% of baseline pages are
fetched.

The canonical baseline is recorded on the **Linux GitHub Actions runner** via
the manual `perf-record` job (which uploads the file as an artifact for a human
merge). See `tests/perf/README.md` for the current reference and regeneration
steps. Local regeneration on Windows records duration/pages only (no RSS).

If `perf-check` starts failing on noisy shared runners without a real code
change, flip `continue-on-error` in the workflow to true temporarily and file
an issue — never weaken the test itself.

## Flaky-test policy

A flaky test is a known-intermittent failure. Handling:

1. **Mark it**: add `@pytest.mark.flaky` to the test (declared in
   `pyproject.toml`; the marker is only for reporting/issue-tracking).
2. **File an issue** describing the intermittent failure and the suspected root
   cause.
3. **Fix the root cause**, then **remove the marker**.

The marker NEVER deselects the test. The suite job deliberately does not use
`not flaky`, so a flaky test keeps running — and keeps failing loudly — until
it is fixed. Deselecting would hide the problem; the DoD is "zero known flaky
tests", verified by the manual `flaky-check` job (suite ×3, any failure fails
the run), not by skipping them.
