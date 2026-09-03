"""Pytest options for the performance baseline test (tests/perf/).

Adds two mutually-exclusive opt-in flags:
  --perf-record   run the perf crawl and write tests/perf/baseline.json
  --perf-check    run the perf crawl and compare against baseline.json
                  with a x3 tolerance (regression detector, not a benchmark)

Without either flag the perf test is skipped (never runs in normal CI).
"""


def pytest_addoption(parser):
    group = parser.getgroup("perf")
    group.addoption(
        "--perf-record",
        action="store_true",
        default=False,
        help="Record crawl duration/max_rss into tests/perf/baseline.json",
    )
    group.addoption(
        "--perf-check",
        action="store_true",
        default=False,
        help="Compare crawl duration/max_rss against tests/perf/baseline.json (x3 tolerance)",
    )


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Report tests marked @pytest.mark.flaky that ran.

    Flaky tests are NOT deselected (see the CI policy: mark → root-cause →
    fix → unmark). This summary makes them visible so a known-intermittent
    test cannot be silently "green" forever.
    """
    flaky_runs = [
        rep
        for rep in terminalreporter.stats.get("passed", [])
        if "flaky" in rep.keywords or (rep.nodeid and "flaky" in str(rep.keywords))
    ]
    flaky_fail = [
        rep
        for rep in terminalreporter.stats.get("failed", [])
        if "flaky" in rep.keywords
    ]
    if flaky_runs or flaky_fail:
        terminalreporter.write_sep("-", "flaky marker report", green=True)
        if flaky_runs:
            terminalreporter.write_line(f"  flaky tests passed : {len(flaky_runs)}")
        if flaky_fail:
            terminalreporter.write_line(
                f"  flaky tests FAILED  : {len(flaky_fail)} — root-cause required before unmarking"
            )
