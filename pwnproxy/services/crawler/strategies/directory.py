"""Directory bruteforce strategy: probe URLs against wordlists.

Moved from ``CrawlerWorker._run_bruteforce`` without rewriting logic.
The function signature takes explicit dependencies (no ``self``) so it
is independently testable.
"""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

from pwnproxy.services.crawler.fetcher import Fetcher as _DefaultFetcher, learn_baseline
from pwnproxy.shared.observability import gen_correlation_id, set_correlation_id

if TYPE_CHECKING:
    from pwnproxy.services.crawler.events import EventPublisher
    from pwnproxy.services.crawler.storage import DiscoveredURLStorage
    from pwnproxy.services.crawler.lifecycle import BruteforceStartConfig
    from pwnproxy.services.jobs.lifecycle import JobLifecycle
    from pwnproxy.services.session.manager import ScopeConfig

logger = logging.getLogger(__name__)


async def run_bruteforce(
    job_id: int | None,
    config: "BruteforceStartConfig",
    *,
    scope: "ScopeConfig",
    ssl_insecure: bool,
    storage: "DiscoveredURLStorage | None",
    lifecycle: "JobLifecycle | None",
    events: "EventPublisher",
    state: dict,
    fetcher_cls=None,
) -> None:
    """Execute a directory bruteforce against base URLs.

    ``state`` is the shared mutable coordinator state dict (``active_task``,
    ``active_job_id``, ``stop_requested``).
    """
    set_correlation_id(gen_correlation_id())
    try:
        if storage is None:
            raise RuntimeError("DiscoveredURLStorage not initialized")
        fetcher = (fetcher_cls or _DefaultFetcher)(rate_limit=config.rate_limit, verify=not ssl_insecure)
        await fetcher.start()
        try:
            # Build URL queue: for each base_url × word × (1 + extensions).
            urls: list[tuple[str, str]] = []  # (url, base)
            for base in config.base_urls:
                base_clean = base.rstrip('/')
                for word in config.wordlist:
                    urls.append((f"{base_clean}/{word}", base_clean))
                    for ext in config.extensions:
                        urls.append((f"{base_clean}/{word}{ext}", base_clean))

            # max_requests backstop: hard cap on probes actually sent.
            maxed = len(urls) > config.max_requests
            if maxed:
                urls = urls[:config.max_requests]
            total_planned = len(urls)

            # Baseline anti soft-404, learned per base URL.
            baselines: dict[str, set[tuple[int, int]]] = {}
            if config.detect_soft404:
                for base in dict.fromkeys(b.rstrip('/') for b in config.base_urls):
                    baselines[base] = await learn_baseline(fetcher, base)

            # Probing loop with concurrency semaphore.
            sem = asyncio.Semaphore(config.concurrency)
            probed = 0
            found = 0
            errors = 0
            skipped = 0
            soft404_filtered = 0
            last_progress = datetime.now(timezone.utc)

            async def _probe_one(url: str) -> tuple[str, tuple[int, int, str] | None, str]:
                async with sem:
                    if state["stop_requested"]:
                        return url, None, "stopped"
                    if not scope.is_in_scope(url):
                        return url, None, "out_of_scope"
                    try:
                        result = await fetcher.probe(url)
                    except Exception:
                        return url, None, "error"
                    return url, result, "ok"

            batch_size = 50
            stopped_cooperatively = False
            for i in range(0, len(urls), batch_size):
                if state["stop_requested"]:
                    stopped_cooperatively = True
                    break
                batch = urls[i:i + batch_size]
                tasks = [asyncio.create_task(_probe_one(u)) for u, _b in batch]
                results = await asyncio.gather(*tasks)

                for (url, base), (_u, probe_result, reason) in zip(batch, results):
                    if reason == "stopped":
                        stopped_cooperatively = True
                        skipped += 1
                        continue
                    if reason == "out_of_scope":
                        skipped += 1
                        continue
                    if probe_result is None or reason == "error":
                        errors += 1
                        continue

                    probed += 1
                    status_code, content_length, _ctype = probe_result

                    # Status filter.
                    if status_code not in config.status_filter:
                        continue

                    # Soft-404 baseline filter.
                    if config.detect_soft404 and (status_code, content_length) in baselines.get(base, set()):
                        soft404_filtered += 1
                        continue

                    # Hit!
                    found += 1
                    new_id = await storage.save(
                        url=url, source="bruteforce", method="GET",
                        base_url=base + '/',
                    )
                    if new_id is not None:
                        await events.discovered_url({
                            "id": new_id,
                            "url": url,
                            "source": "bruteforce",
                            "method": "GET",
                            "base_url": base + '/',
                        })

                now = datetime.now(timezone.utc)
                if (now - last_progress).total_seconds() >= 1.0:
                    await events.bruteforce_progress(job_id, {
                        "probed": probed, "found": found, "errors": errors,
                        "skipped": skipped, "soft404_filtered": soft404_filtered,
                        "total_planned": total_planned, "maxed": maxed,
                    })
                    last_progress = now

            # Cooperative stop: stop handler already marks the job stopped.
            if stopped_cooperatively:
                return

            # Final stats.
            stats = {
                "probed": probed, "found": found, "errors": errors,
                "skipped": skipped, "soft404_filtered": soft404_filtered,
                "total_planned": total_planned, "maxed": maxed,
            }
            await events.bruteforce_progress(job_id, stats)

            if lifecycle and job_id:
                await lifecycle.update_stats(job_id, stats)
                await lifecycle.complete(job_id)
            await events.bruteforce_completed(job_id, stats)

        finally:
            await fetcher.stop()

    except asyncio.CancelledError:
        if lifecycle and job_id:
            await lifecycle.safe_cancel(job_id)
        if not state["stop_requested"]:
            await events.bruteforce_failed(job_id, "cancelled")

    except Exception as exc:
        logger.exception("Bruteforce job %s failed", job_id)
        if lifecycle and job_id:
            await lifecycle.safe_fail(job_id, str(exc))
        await events.bruteforce_failed(job_id, str(exc))

    finally:
        state["active_task"] = None
        state["active_job_id"] = None
        state["stop_requested"] = False
