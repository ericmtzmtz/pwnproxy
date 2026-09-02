"""Tests for the AutoScanTracker (windowed auto-scan batch events)."""
import asyncio

import pytest

from pwnproxy.plugins.core.autoscan import AutoScanTracker


class FakeHookBus:
    def __init__(self):
        self.published: list[tuple[str, dict]] = []

    def publish(self, topic, payload):
        self.published.append((topic, payload))


class FakeFlow:
    def __init__(self, fid):
        self.id = fid


class TestAutoScanTracker:
    @pytest.mark.asyncio
    async def test_flow_dedup_and_batch_completion(self):
        bus = FakeHookBus()
        t = AutoScanTracker(hook_bus=bus, window_s=0.2)
        # Same flow reported by multiple plugins → counted once
        await t.report_flow(FakeFlow("f1"))
        await t.report_flow(FakeFlow("f1"))
        await t.report_flow(FakeFlow("f2"))
        await t.report_finding()
        await t.report_finding()

        # close active batch manually (as stop() would)
        await t.close_active()

        topics = [tp for tp, _ in bus.published]
        assert "autoscan.started" in topics
        assert "autoscan.completed" in topics

        status = t.status()
        assert status["running"] is False
        assert status["last"]["flows"] == 2
        assert status["last"]["findings"] == 2

    @pytest.mark.asyncio
    async def test_window_rolls_new_batch_after_idle(self):
        bus = FakeHookBus()
        t = AutoScanTracker(hook_bus=bus, window_s=0.05)
        await t.report_flow(FakeFlow("f1"))
        await asyncio.sleep(0.15)  # exceed idle window
        await t.report_flow(FakeFlow("f2"))
        await t.close_active()

        started = [p for tp, p in bus.published if tp == "autoscan.started"]
        completed = [p for tp, p in bus.published if tp == "autoscan.completed"]
        assert len(started) == 2  # two windows opened
        assert len(completed) == 2  # both closed
        # each batch had exactly one flow
        assert all(p["flows"] == 1 for p in started)

    @pytest.mark.asyncio
    async def test_status_while_running(self):
        bus = FakeHookBus()
        t = AutoScanTracker(hook_bus=bus, window_s=5.0)
        await t.report_flow(FakeFlow("f1"))
        await t.report_finding()
        status = t.status()
        assert status["running"] is True
        assert status["active"]["flows"] == 1
        assert status["active"]["findings"] == 1
        assert status["last"] is None
        await t.close_active()

    @pytest.mark.asyncio
    async def test_idle_flush_closes_batch_without_reopening(self):
        """Regression: idle time must NOT keep auto-scan 'running' with an empty batch."""
        bus = FakeHookBus()
        t = AutoScanTracker(hook_bus=bus, window_s=0.05)
        await t.report_flow(FakeFlow("f1"))
        assert t.status()["running"] is True

        t.start()
        try:
            await asyncio.sleep(0.2)  # exceeds idle window -> flush closes batch
        finally:
            await t.stop()

        status = t.status()
        assert status["running"] is False
        assert status["active"] is None
        assert status["last"] is not None
        assert status["last"]["flows"] == 1

        # a new flow opens a fresh batch (started event emitted again)
        await t.report_flow(FakeFlow("f2"))
        assert t.status()["running"] is True
        assert t.status()["active"]["flows"] == 1
        await t.close_active()
