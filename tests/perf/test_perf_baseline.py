"""Performance baseline: opt-in regression detector.

Run with:
    poetry run pytest tests/perf/ -m perf --perf-record   # write baseline
    poetry run pytest tests/perf/ -m perf --perf-check    # compare (x3 tolerance)

Without --perf-record or --perf-check the test is skipped.
max_rss is best-effort (recorded only where ``resource`` module is available, i.e. Linux).
"""

import asyncio
import json
import time
from pathlib import Path

import pytest
from aiohttp import web

from pwnproxy.services.crawler.engine import CrawlConfig, CrawlEngine
from pwnproxy.services.crawler.fetcher import Fetcher
from pwnproxy.services.session.manager import ScopeConfig

pytestmark = pytest.mark.perf

BASELINE = Path(__file__).parent / "baseline.json"
TOLERANCE = 3.0
N_PAGES = 30
DEPTH = 3
FLOWS: list[dict] = []


def _try_max_rss():
    """Best-effort peak RSS in KB. Returns None on Windows."""
    try:
        import resource
        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    except (ImportError, AttributeError):
        return None


def _build_app():
    """Build an aiohttp app with N_PAGES linked pages (branching tree)."""
    routes = {}

    def _page(name, links=None):
        hrefs = "".join(f'<a href="/{l}">{l}</a> ' for l in (links or []))
        return web.Response(
            text=f"<html><body><h1>{name}</h1>{hrefs}</body></html>",
            content_type="text/html",
        )

    routes["/"] = lambda r: _page("root", links=["page1", "page2", "page3"])
    for i in range(1, N_PAGES):
        name = f"page{i}"
        links = [f"page{i * 2 + 1}", f"page{i * 2 + 2}"] if i * 2 + 1 <= N_PAGES else []
        routes[f"/{name}"] = (lambda r, n=name, lk=links: _page(n, links=lk))

    app = web.Application()
    for path, handler in routes.items():
        app.router.add_get(path, handler)
    return app


async def _run_crawl(seed_url: str):
    """Run CrawlEngine with real Fetcher against seed_url."""
    fetcher = Fetcher(rate_limit=200, verify=False)
    await fetcher.start()
    try:
        config = CrawlConfig(
            seeds=[seed_url],
            depth=DEPTH,
            rate_limit=200,
            concurrency=10,
            max_urls=N_PAGES + 50,
            respect_robots=False,
            include_discovered=False,
            scan_while_crawl=False,
        )
        scope = ScopeConfig({"enabled": True, "in_scope": ["*"]})
        engine = CrawlEngine(config=config, scope=scope, verify=False)
        flows = []
        async for flow in engine.run(fetcher):
            flows.append(flow)
        return flows
    finally:
        await fetcher.stop()


async def _measure(seed_url: str) -> dict:
    """Run crawl, return {duration_ms, max_rss_kb, pages_fetched, errors}."""
    t0 = time.monotonic()
    flows = await _run_crawl(seed_url)
    elapsed_ms = round((time.monotonic() - t0) * 1000, 1)
    max_rss = _try_max_rss()
    return {
        "duration_ms": elapsed_ms,
        "max_rss_kb": max_rss,
        "pages_fetched": len(flows),
        "errors": sum(1 for f in flows if f.get("status_code", 200) >= 400),
    }


# ── Tests ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_perf_baseline(request):
    """Run crawl against a local HTTP server and record/check baseline."""
    record = request.config.getoption("--perf-record", default=False)
    check = request.config.getoption("--perf-check", default=False)
    if not record and not check:
        pytest.skip("Use --perf-record or --perf-check to run the perf baseline")

    # Spin up local HTTP server
    app = _build_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    port = site._server.sockets[0].getsockname()[1]
    seed_url = f"http://127.0.0.1:{port}/"

    try:
        result = await _measure(seed_url)
    finally:
        await runner.cleanup()

    if record:
        BASELINE.parent.mkdir(parents=True, exist_ok=True)
        BASELINE.write_text(json.dumps(result, indent=2))
        print(f"\n  baseline recorded → {BASELINE}")
        print(f"    duration_ms : {result['duration_ms']}")
        print(f"    max_rss_kb  : {result['max_rss_kb']}")
        print(f"    pages_fetched: {result['pages_fetched']}")
        print(f"    errors      : {result['errors']}")
    elif check:
        assert BASELINE.exists(), f"baseline not found: {BASELINE}\nRun with --perf-record first"
        baseline = json.loads(BASELINE.read_text())
        print(f"\n  baseline: {baseline}")
        print(f"  current : {result}")

        dur_ratio = result["duration_ms"] / max(baseline["duration_ms"], 1)
        pages_diff = abs(result["pages_fetched"] - baseline["pages_fetched"])
        pages_ratio = result["pages_fetched"] / max(baseline["pages_fetched"], 1)

        # Duration regression check
        assert dur_ratio <= TOLERANCE, (
            f"PERF REGRESSION: duration {result['duration_ms']}ms is "
            f"{dur_ratio:.1f}x the baseline {baseline['duration_ms']}ms "
            f"(tolerance: {TOLERANCE}x)"
        )

        # Page count: must fetch at least the same number (±10%)
        assert pages_ratio >= 0.9, (
            f"PERF REGRESSION: fetched {result['pages_fetched']} pages vs "
            f"baseline {baseline['pages_fetched']} (tolerance: ±10%)"
        )

        print(f"\n  duration ratio: {dur_ratio:.2f}x (ok)")
        print(f"  pages ratio   : {pages_ratio:.2f}x (ok)")
