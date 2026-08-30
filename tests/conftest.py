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
