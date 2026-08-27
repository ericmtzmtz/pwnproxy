import json
import logging
from datetime import datetime, timezone
from typing import Any, Optional

from sqlalchemy import Column, Integer, String, Text, DateTime
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import DeclarativeBase, sessionmaker

logger = logging.getLogger(__name__)

# Sentinel: distinguish "leave the error column untouched" from "set to NULL".
_UNSET = object()


class CrawlerBase(DeclarativeBase):
    """Dedicated metadata so discovered_urls is never created inside
    traffic.db / scanner_results.db by shared Base.metadata.create_all()."""


class DiscoveredURLORM(CrawlerBase):
    __tablename__ = "discovered_urls"

    id = Column(Integer, primary_key=True, autoincrement=True)
    url = Column(Text, nullable=False, unique=True, index=True)
    base_url = Column(Text, default="")
    method = Column(String(10), default="GET")
    source = Column(String(20), default="")
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc))


class JobORM(CrawlerBase):
    __tablename__ = "jobs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    type = Column(String(20), nullable=False, default="active")
    status = Column(String(20), nullable=False, default="queued")
    config = Column(Text, nullable=False, default="{}")
    stats = Column(Text, nullable=False, default="{}")
    error = Column(Text, nullable=True)
    tenant_id = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)


class DiscoveredURLStorage:
    def __init__(self, engine):
        self._engine = engine
        self._factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def create_table(self) -> None:
        async with self._engine.begin() as conn:
            await conn.run_sync(
                lambda sync_conn: DiscoveredURLORM.__table__.create(sync_conn, checkfirst=True)
            )
            await conn.run_sync(
                lambda sync_conn: JobORM.__table__.create(sync_conn, checkfirst=True)
            )
        # Enable WAL: the crawler worker writes while the API process reads.
        from sqlalchemy import text
        try:
            async with self._engine.begin() as conn:
                await conn.execute(text("PRAGMA journal_mode=WAL"))
        except Exception:
            logger.debug("could not enable WAL on crawler db", exc_info=True)
        # Additive migration for pre-existing tables (FindingStorage pattern).
        async with self._engine.begin() as conn:
            cols = await conn.execute(text("SELECT name FROM pragma_table_info('discovered_urls')"))
            names = {row[0] for row in cols}
            if not names:
                return
            for column, ddl in (
                ("base_url", "TEXT DEFAULT ''"),
                ("method", "VARCHAR(10) DEFAULT 'GET'"),
                ("source", "VARCHAR(20) DEFAULT ''"),
            ):
                if column not in names:
                    await conn.execute(text(f"ALTER TABLE discovered_urls ADD COLUMN {column} {ddl}"))
                    logger.info("Migrated discovered_urls table: added %s column", column)

    async def save(self, url: str, source: str = "", method: str = "GET", base_url: str = "") -> Optional[int]:
        """Insert a discovered URL. Returns the new row id, or None if duplicate."""
        record = DiscoveredURLORM(url=url, source=source or "", method=method or "GET", base_url=base_url or "")
        async with self._factory() as session:
            existing = await session.execute(
                DiscoveredURLORM.__table__.select().where(DiscoveredURLORM.url == url)
            )
            if existing.first() is not None:
                return None
            session.add(record)
            try:
                await session.commit()
            except Exception:
                # Lost a race (unique index) — treat as duplicate.
                await session.rollback()
                return None
            return record.id

    @staticmethod
    def _row_dict(record: DiscoveredURLORM) -> dict:
        return {c.name: getattr(record, c.name) for c in DiscoveredURLORM.__table__.columns}

    async def list(self, source: Optional[str] = None, limit: int = 100, offset: int = 0) -> list[dict]:
        from sqlalchemy import select
        async with self._factory() as session:
            query = select(DiscoveredURLORM)
            if source:
                query = query.where(DiscoveredURLORM.source == source)
            query = query.order_by(DiscoveredURLORM.id.desc()).limit(limit).offset(offset)
            result = await session.execute(query)
            rows = result.scalars().all()
            return [self._row_dict(r) for r in rows]

    async def count(self, source: Optional[str] = None) -> int:
        from sqlalchemy import select, func
        async with self._factory() as session:
            query = select(func.count(DiscoveredURLORM.id))
            if source:
                query = query.where(DiscoveredURLORM.source == source)
            result = await session.execute(query)
            return result.scalar() or 0


class JobStorage:
    def __init__(self, engine):
        self._engine = engine
        self._factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)

    async def create(self, job_type: str = "active", config: Optional[dict] = None) -> int:
        """Create a new job and return its id."""
        now = datetime.now(timezone.utc)
        record = JobORM(
            type=job_type,
            status="queued",
            config=json.dumps(config or {}),
            stats="{}",
            created_at=now,
        )
        async with self._factory() as session:
            session.add(record)
            await session.commit()
            return record.id  # type: ignore[return-value]

    async def get(self, job_id: int) -> Optional[dict]:
        """Fetch a job by id, or None."""
        from sqlalchemy import select
        async with self._factory() as session:
            result = await session.execute(
                select(JobORM).where(JobORM.id == job_id)
            )
            row = result.scalar_one_or_none()
            if row is None:
                return None
            return self._row_dict(row)

    async def list_active(self) -> list[dict]:
        """Return all queued or running jobs."""
        from sqlalchemy import select
        async with self._factory() as session:
            result = await session.execute(
                select(JobORM)
                .where(JobORM.status.in_(["queued", "running"]))
                .order_by(JobORM.id)
            )
            return [self._row_dict(r) for r in result.scalars().all()]

    async def list_all(self, limit: int = 50) -> list[dict]:
        """Return jobs ordered by most recent."""
        from sqlalchemy import select
        async with self._factory() as session:
            result = await session.execute(
                select(JobORM).order_by(JobORM.id.desc()).limit(limit)
            )
            return [self._row_dict(r) for r in result.scalars().all()]

    async def update_status(
        self,
        job_id: int,
        status: str,
        error: Any = _UNSET,
        expected_status: Optional[str] = None,
    ) -> int:
        """Low-level status write. PREFER ``transition_status`` — it enforces
        the JobState machine; this method only validates enum membership.

        ``expected_status`` turns the write into a compare-and-set: the row
        is updated only if its current status matches, and the number of
        affected rows is returned (0 = lost race).

        ``error`` default is a sentinel: when omitted the error column is
        left untouched; pass ``None`` explicitly to clear it.
        """
        from pwnproxy.shared.contracts.job import JobState, _LEGACY_MAP
        canonical = _LEGACY_MAP.get(status, status)
        try:
            JobState(canonical)
        except ValueError:
            raise ValueError(f"Invalid job status: {status!r}")
        from sqlalchemy import update
        now = datetime.now(timezone.utc)
        values: dict[str, Any] = {"status": status}
        if error is not _UNSET:
            values["error"] = error
        if status == "running":
            values["started_at"] = now
        elif status in ("completed", "failed", "stopped", "cancelled"):
            values["finished_at"] = now
        async with self._factory() as session:
            stmt = update(JobORM).where(JobORM.id == job_id)
            if expected_status is not None:
                stmt = stmt.where(JobORM.status == expected_status)
            result = await session.execute(stmt.values(**values))
            await session.commit()
            return result.rowcount

    async def update_stats(self, job_id: int, stats: dict) -> None:
        """Replace the JSON stats blob."""
        from sqlalchemy import update
        async with self._factory() as session:
            await session.execute(
                update(JobORM).where(JobORM.id == job_id).values(stats=json.dumps(stats))
            )
            await session.commit()

    async def mark_stale_running_failed(self) -> int:
        """Mark any jobs stuck in 'running' as 'failed' (crash recovery).
        Uses the state machine (RUNNING→FAILED is a legal transition).
        Returns the number of affected rows."""
        from sqlalchemy import select
        async with self._factory() as session:
            result = await session.execute(
                select(JobORM.id).where(JobORM.status == "running")
            )
            running_ids = [row[0] for row in result.fetchall()]
        count = 0
        for jid in running_ids:
            try:
                # expected_state=RUNNING: if another actor moved the job since
                # the SELECT, transition_status skips it (no write).
                new_status = await self.transition_status(
                    jid, "failed", error="worker restarted", expected_state="running"
                )
                if new_status == "failed":
                    count += 1
            except Exception:
                logger.exception("Crash recovery: failed to mark stale job %s as failed", jid)
        return count

    async def clone_job(self, original_id: int) -> int:
        """Create a new job from an existing one (for retry after terminal state).

        Returns the new job id. The original job is NOT modified.
        """
        original = await self.get(original_id)
        if original is None:
            raise ValueError(f"Job {original_id} not found")
        now = datetime.now(timezone.utc)
        record = JobORM(
            type=original["type"],
            status="created",
            config=original["config"],
            stats="{}",
            created_at=now,
        )
        async with self._factory() as session:
            session.add(record)
            await session.commit()
            return record.id  # type: ignore[return-value]

    async def transition_status(
        self,
        job_id: int,
        target_status: str,
        error: Optional[str] = None,
        expected_state: Optional[str] = None,
    ) -> str:
        """Load a job, validate the transition via the canonical JobState
        machine, and persist every step with an atomic compare-and-set.

        Returns the final status string (the winner's state if the race
        was lost).

        Idempotent: ``current == target`` is a no-op returning the current
        status. Transitions OUT of a terminal state (COMPLETED/FAILED/
        CANCELLED) raise ``InvalidJobTransition`` — a terminal job trying to
        move is a bug, not a no-op (e.g. FAILED → COMPLETED must fail loudly).

        ``expected_state`` guards against TOCTOU: if the job is not in the
        expected state when read, nothing is written and the current status
        is returned (the other writer won).

        Operation commands walk their implicit legal path and PERSIST every
        intermediate state (each step is a CAS UPDATE WHERE status = prev):
          start:  CREATED → STARTING → RUNNING
          stop:   RUNNING → STOPPING → CANCELLED

        If any CAS step affects 0 rows, another writer won the race: the
        transition stops and the winner's current status is returned.
        """
        from pwnproxy.shared.contracts.job import (
            Job,
            JobState,
            InvalidJobTransition,
            TERMINAL_STATES,
            transition as job_transition,
        )
        raw = await self.get(job_id)
        if raw is None:
            raise ValueError(f"Job {job_id} not found")
        # The actual status string in the DB — may be a legacy value
        # (e.g. "queued") that the CAS must match against on the first step.
        raw_status = raw.get("status", "created")
        # Remap ORM column names → contract field names and deserialize JSON blobs
        import json as _json
        job_data = {
            **raw,
            "state": raw.pop("status", "created"),
            "config": _json.loads(raw.get("config") or "{}"),
            "stats": _json.loads(raw.get("stats") or "{}"),
        }
        job = Job.model_validate(job_data)
        current = JobState(job.state) if isinstance(job.state, str) else job.state
        target = JobState(target_status) if isinstance(target_status, str) else target_status
        # Idempotent: already in target → no-op.
        if current == target:
            return current.value
        # TOCTOU guard: another writer changed the state since the caller
        # decided to act — skip without touching anything.
        if expected_state is not None and current != JobState(expected_state):
            return current.value
        # Terminal states have no exit: raise instead of silently ignoring.
        if current in TERMINAL_STATES:
            raise InvalidJobTransition(
                f"Cannot transition terminal job {current.value!r} -> {target.value!r}"
            )

        # Build the full path of states to persist (implicit legal steps first).
        path: list[JobState] = []
        if target == JobState.RUNNING and current == JobState.CREATED:
            path.append(JobState.STARTING)
        if target == JobState.CANCELLED and current in (JobState.RUNNING, JobState.STARTING):
            path.append(JobState.STOPPING)
        path.append(target)

        prev_value = raw_status
        for index, step in enumerate(path):
            job_transition(job, step)  # raises InvalidJobTransition if illegal
            step_value = job.state if isinstance(job.state, str) else job.state.value
            step_error = error if index == len(path) - 1 else _UNSET
            affected = await self.update_status(
                job_id, step_value, error=step_error, expected_status=prev_value
            )
            if affected == 0:
                # Lost the race: another writer changed the state. Report the
                # winner's status; do not touch the row.
                latest = await self.get(job_id)
                if latest is None:
                    raise ValueError(f"Job {job_id} disappeared during transition")
                logger.warning(
                    "Job %s transition to %s lost race (expected %s, now %s)",
                    job_id, target.value, prev_value, latest["status"],
                )
                return latest["status"]
            prev_value = step_value
        return prev_value

    @staticmethod
    def _row_dict(record: JobORM) -> dict:
        return {c.name: getattr(record, c.name) for c in JobORM.__table__.columns}
