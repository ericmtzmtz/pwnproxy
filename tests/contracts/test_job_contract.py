"""Tests for shared contracts: Job, JobState, transition()."""

import pytest
from pydantic import ValidationError

from pwnproxy.shared.contracts.job import (
    TERMINAL_STATES,
    BruteforceStats,
    CrawlStats,
    InvalidJobTransition,
    Job,
    JobState,
    transition,
)


class TestJobStateEnum:
    def test_all_seven_states_exist(self):
        assert len(JobState) == 7
        expected = {"created", "starting", "running", "stopping",
                    "completed", "failed", "cancelled"}
        assert {s.value for s in JobState} == expected

    def test_legacy_string_coercion(self):
        """Legacy DB strings map to canonical JobState values."""
        j = Job(id=1, type="active", state="queued")
        assert j.state == JobState.CREATED.value

        j2 = Job(id=2, type="active", state="stopped")
        assert j2.state == JobState.CANCELLED.value

    def test_invalid_string_rejected(self):
        with pytest.raises(ValidationError):
            Job(id=1, type="active", state="bogus")


class TestTransition:
    def test_legal_transitions(self):
        j = Job(id=1, type="active", state=JobState.CREATED)
        assert transition(j, JobState.STARTING) == JobState.STARTING
        assert transition(j, JobState.RUNNING) == JobState.RUNNING
        assert transition(j, JobState.COMPLETED) == JobState.COMPLETED

    def test_illegal_transition_raises(self):
        j = Job(id=1, type="active", state=JobState.CREATED)
        with pytest.raises(InvalidJobTransition):
            transition(j, JobState.COMPLETED)  # CREATED → COMPLETED not legal

    def test_terminal_no_exit(self):
        for terminal in (JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED):
            j = Job(id=1, type="active", state=terminal)
            for target in JobState:
                if target == terminal:
                    continue
                with pytest.raises(InvalidJobTransition):
                    transition(j, target)

    def test_started_at_set_on_running(self):
        j = Job(id=1, type="active", state=JobState.CREATED)
        assert j.started_at is None
        transition(j, JobState.STARTING)
        assert j.started_at is None
        transition(j, JobState.RUNNING)
        assert j.started_at is not None

    def test_finished_at_set_on_terminal(self):
        j = Job(id=1, type="active", state=JobState.RUNNING)
        assert j.finished_at is None
        transition(j, JobState.COMPLETED)
        assert j.finished_at is not None


class TestJobModel:
    def test_serializes_to_dict(self):
        j = Job(id=42, type="bruteforce", state=JobState.RUNNING,
                stats=BruteforceStats(probed=100))
        d = j.model_dump(mode="json")
        assert d["id"] == 42
        assert d["state"] == "running"
        assert d["stats"]["probed"] == 100

    def test_roundtrip(self):
        j = Job(id=1, type="active", state=JobState.RUNNING,
                stats=CrawlStats(fetched=10))
        d = j.model_dump(mode="json")
        j2 = Job.model_validate(d)
        assert j2.state == "running"
        assert j2.stats.fetched == 10


class TestJobStats:
    def test_crawl_stats_defaults(self):
        s = CrawlStats()
        assert s.fetched == 0
        assert s.queued == 0

    def test_bruteforce_stats_defaults(self):
        s = BruteforceStats()
        assert s.probed == 0
        assert s.maxed is False


class TestJobStorageValidation:
    @pytest.mark.asyncio
    async def test_update_status_rejects_invalid(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        js = JobStorage(engine)
        from pwnproxy.services.crawler.storage import DiscoveredURLStorage
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()

        job_id = await js.create(job_type="active")
        with pytest.raises(ValueError, match="Invalid job status"):
            await js.update_status(job_id, "bogus_status")
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_update_status_accepts_valid(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        js = JobStorage(engine)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()

        job_id = await js.create(job_type="active")
        await js.update_status(job_id, "running")
        job = await js.get(job_id)
        assert job["status"] == "running"
        await engine.dispose()


# ── 3.5 Full transition table tests ─────────────────────────────────────


class TestFullTransitionTable:
    """Exhaustive legal/illegal transition verification."""

    def test_all_legal_transitions(self):
        """Every transition in the legal table succeeds."""
        legal_table = {
            JobState.CREATED:  [JobState.STARTING, JobState.CANCELLED],
            JobState.STARTING: [JobState.RUNNING, JobState.FAILED, JobState.STOPPING],
            JobState.RUNNING:  [JobState.STOPPING, JobState.COMPLETED, JobState.FAILED],
            JobState.STOPPING: [JobState.CANCELLED, JobState.FAILED],
        }
        for current, targets in legal_table.items():
            for target in targets:
                j = Job(id=1, type="active", state=current)
                result = transition(j, target)
                assert result == target
                assert j.state == target.value

    def test_illegal_transitions(self):
        """Every non-legal transition raises InvalidJobTransition."""
        illegal_table = {
            JobState.CREATED:  [JobState.RUNNING, JobState.COMPLETED, JobState.FAILED,
                                JobState.STOPPING],
            JobState.STARTING: [JobState.CREATED, JobState.COMPLETED, JobState.CANCELLED],
            JobState.RUNNING:  [JobState.CREATED, JobState.STARTING, JobState.CANCELLED],
            JobState.STOPPING: [JobState.CREATED, JobState.STARTING, JobState.RUNNING,
                                JobState.COMPLETED],
        }
        for current, targets in illegal_table.items():
            for target in targets:
                j = Job(id=1, type="active", state=current)
                with pytest.raises(InvalidJobTransition, match=f"Cannot transition"):
                    transition(j, target)
                # Job state must remain unchanged after illegal transition
                assert j.state == current.value


class TestTerminalImmutables:
    """Terminal states (COMPLETED/FAILED/CANCELLED) have no outgoing transitions."""

    def test_cannot_exit_completed(self):
        j = Job(id=1, type="active", state=JobState.COMPLETED)
        for s in JobState:
            if s == JobState.COMPLETED:
                continue
            with pytest.raises(InvalidJobTransition):
                transition(j, s)
            assert j.state == JobState.COMPLETED.value

    def test_cannot_exit_failed(self):
        j = Job(id=1, type="active", state=JobState.FAILED)
        for s in JobState:
            if s == JobState.FAILED:
                continue
            with pytest.raises(InvalidJobTransition):
                transition(j, s)
            assert j.state == JobState.FAILED.value

    def test_cannot_exit_cancelled(self):
        j = Job(id=1, type="active", state=JobState.CANCELLED)
        for s in JobState:
            if s == JobState.CANCELLED:
                continue
            with pytest.raises(InvalidJobTransition):
                transition(j, s)
            assert j.state == JobState.CANCELLED.value

    def test_all_terminal_states_covered(self):
        assert TERMINAL_STATES == frozenset({
            JobState.COMPLETED, JobState.FAILED, JobState.CANCELLED,
        })


class TestRetryCloneJob:
    """Retry after terminal state creates a new job via clone_job."""

    @pytest.mark.asyncio
    async def test_clone_creates_new_job(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        original_id = await js.create(job_type="active", config={"seeds": ["https://a.com"]})
        await js.update_status(original_id, "running")
        await js.update_status(original_id, "completed")

        original = await js.get(original_id)
        assert original["status"] == "completed"

        new_id = await js.clone_job(original_id)
        assert new_id != original_id

        new_job = await js.get(new_id)
        assert new_job["status"] == "created"
        assert new_job["type"] == "active"
        # Config is preserved
        import json
        assert json.loads(new_job["config"])["seeds"] == ["https://a.com"]
        # Original unchanged
        original2 = await js.get(original_id)
        assert original2["status"] == "completed"
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_clone_nonexistent_raises(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        with pytest.raises(ValueError, match="not found"):
            await js.clone_job(9999)
        await engine.dispose()


class TestStopIdempotent:
    """STOP on already-cancelled/stopping job is idempotent."""

    @pytest.mark.asyncio
    async def test_transition_cancelled_is_idempotent(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        jid = await js.create(job_type="active")
        # Go through proper path: created→starting→running→stopping→cancelled
        await js.transition_status(jid, "starting")
        await js.transition_status(jid, "running")
        await js.transition_status(jid, "stopping")
        status = await js.transition_status(jid, "cancelled")
        assert status in ("cancelled", JobState.CANCELLED.value)

        # Second transition to cancelled on already-terminal → idempotent
        status2 = await js.transition_status(jid, "cancelled")
        assert status2 in ("cancelled", JobState.CANCELLED.value)
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_transition_failed_is_idempotent(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        jid = await js.create(job_type="active")
        # Go through proper path: created→starting→running→failed
        await js.transition_status(jid, "starting")
        await js.transition_status(jid, "running")
        await js.transition_status(jid, "failed", error="crash")
        job = await js.get(jid)
        assert job["status"] == "failed"

        # Idempotent: already failed
        await js.transition_status(jid, "failed")
        job2 = await js.get(jid)
        assert job2["status"] == "failed"
        await engine.dispose()


class TestTerminalTransitionRejection:
    """Terminal → different state is a BUG: must raise, not silently no-op."""

    @pytest.mark.asyncio
    async def test_failed_to_completed_raises(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        jid = await js.create(job_type="active")
        await js.transition_status(jid, "starting")
        await js.transition_status(jid, "running")
        await js.transition_status(jid, "failed")

        with pytest.raises(InvalidJobTransition, match="terminal"):
            await js.transition_status(jid, "completed")
        # State untouched.
        assert (await js.get(jid))["status"] == "failed"
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_cancelled_to_failed_raises(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        jid = await js.create(job_type="active")
        await js.transition_status(jid, "cancelled")

        with pytest.raises(InvalidJobTransition, match="terminal"):
            await js.transition_status(jid, "failed")
        assert (await js.get(jid))["status"] == "cancelled"
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_completed_to_running_raises(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        jid = await js.create(job_type="active")
        await js.transition_status(jid, "starting")
        await js.transition_status(jid, "running")
        await js.transition_status(jid, "completed")

        with pytest.raises(InvalidJobTransition, match="terminal"):
            await js.transition_status(jid, "running")
        assert (await js.get(jid))["status"] == "completed"
        await engine.dispose()


class TestExpectedStateGuard:
    """expected_state: TOCTOU guard — skip the write if state changed."""

    @pytest.mark.asyncio
    async def test_expected_state_match_transitions(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        jid = await js.create(job_type="active")
        await js.transition_status(jid, "running")
        new_status = await js.transition_status(jid, "failed", expected_state="running")
        assert new_status == "failed"
        assert (await js.get(jid))["status"] == "failed"
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_expected_state_mismatch_skips(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        jid = await js.create(job_type="active")
        await js.transition_status(jid, "running")
        await js.transition_status(jid, "cancelled")  # someone else acted

        # Crash recovery arriving late must not touch the cancelled job.
        new_status = await js.transition_status(jid, "failed", expected_state="running")
        assert new_status == "cancelled"
        assert (await js.get(jid))["status"] == "cancelled"
        await engine.dispose()


class TestConcurrentTransitionRace:
    """The CAS must make concurrent transitions race-safe: at most one actor
    wins; nobody may believe they succeeded with a different final state.

    A late loser may raise InvalidJobTransition (terminal → different state
    is a bug by design) — that is a legitimate outcome of reading the job
    after the winner already wrote.
    """

    @pytest.mark.asyncio
    async def test_complete_and_cancel_race(self, tmp_path):
        import asyncio

        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        jid = await js.create(job_type="active")
        await js.transition_status(jid, "running")

        results = await asyncio.gather(
            js.transition_status(jid, "completed"),
            js.transition_status(jid, "cancelled"),
            return_exceptions=True,
        )
        allowed_errors = (InvalidJobTransition,)
        assert all(
            not isinstance(r, BaseException) or isinstance(r, allowed_errors)
            for r in results
        ), results

        final = (await js.get(jid))["status"]
        assert final in ("completed", "cancelled")

        # Nobody may claim success with a terminal state different from the
        # actual final state: a broken CAS would let both actors report their
        # own target as achieved.
        for r in results:
            if isinstance(r, str) and r in ("completed", "cancelled"):
                assert r == final, f"actor claimed {r} but final state is {final}"
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_fail_and_cancel_race(self, tmp_path):
        import asyncio

        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        jid = await js.create(job_type="active")
        await js.transition_status(jid, "running")

        results = await asyncio.gather(
            js.transition_status(jid, "failed", error="boom"),
            js.transition_status(jid, "cancelled"),
            return_exceptions=True,
        )
        assert all(
            not isinstance(r, BaseException) or isinstance(r, InvalidJobTransition)
            for r in results
        ), results

        final = (await js.get(jid))["status"]
        assert final in ("failed", "cancelled")
        for r in results:
            if isinstance(r, str) and r in ("failed", "cancelled"):
                assert r == final, f"actor claimed {r} but final state is {final}"
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_repeat_races_stay_consistent(self, tmp_path):
        """Run the race several times: every interleaving must stay valid."""
        import asyncio

        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        for _ in range(5):
            jid = await js.create(job_type="active")
            await js.transition_status(jid, "running")
            results = await asyncio.gather(
                js.transition_status(jid, "completed"),
                js.transition_status(jid, "cancelled"),
                return_exceptions=True,
            )
            assert all(
                not isinstance(r, BaseException) or isinstance(r, InvalidJobTransition)
                for r in results
            ), results
            final = (await js.get(jid))["status"]
            assert final in ("completed", "cancelled")
            for r in results:
                if isinstance(r, str) and r in ("completed", "cancelled"):
                    assert r == final
        await engine.dispose()


class TestCrashRecovery:
    """mark_stale_running_failed uses transition() (RUNNING→FAILED)."""

    @pytest.mark.asyncio
    async def test_single_stale_job(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        jid = await js.create(job_type="active")
        await js.update_status(jid, "running")

        count = await js.mark_stale_running_failed()
        assert count == 1
        job = await js.get(jid)
        assert job["status"] == "failed"
        assert job["error"] == "worker restarted"
        assert job["finished_at"] is not None
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_mixed_jobs_only_running_affected(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        j1 = await js.create(job_type="active")
        j2 = await js.create(job_type="active")
        j3 = await js.create(job_type="active")
        await js.update_status(j1, "running")
        await js.update_status(j2, "completed")
        # j3 stays "queued"

        count = await js.mark_stale_running_failed()
        assert count == 1

        assert (await js.get(j1))["status"] == "failed"
        assert (await js.get(j2))["status"] == "completed"  # untouched
        assert (await js.get(j3))["status"] == "queued"     # untouched
        await engine.dispose()

    @pytest.mark.asyncio
    async def test_no_stale_jobs(self, tmp_path):
        from sqlalchemy.ext.asyncio import create_async_engine
        from pwnproxy.services.crawler.storage import JobStorage, DiscoveredURLStorage

        engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'test.db'}", echo=False)
        ds = DiscoveredURLStorage(engine)
        await ds.create_table()
        js = JobStorage(engine)

        count = await js.mark_stale_running_failed()
        assert count == 0
        await engine.dispose()
