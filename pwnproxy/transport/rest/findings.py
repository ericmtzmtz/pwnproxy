import json
import logging
from datetime import UTC, datetime
from typing import Any, Literal

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.findings.events import publish_stored_finding
from pwnproxy.shared.findings.storage import FindingORM

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["findings"])

VALID_TRIAGE_VERDICTS = ("true_positive", "false_positive")

#: Same vocabulary the scanners use; anything else is a client bug, not a finding.
SEVERITIES = ("low", "medium", "high", "critical")
CONFIDENCES = ("tentative", "inferred", "confirmed")
#: Anti-garbage caps (D9): a local process must not be able to inflate the
#: session database with one request.
MAX_EVIDENCE_CHARS = 65_536
MAX_JSON_BYTES = 65_536
MAX_URL_CHARS = 8_192


def _severity_clause(severity: str | None) -> list:
    if not severity:
        return []
    return [s.strip() for s in severity.split(",") if s.strip()]


def _apply_filters(query, scanner: str | None = None, severity: str | None = None,
                   verdict: str | None = None):
    if scanner:
        query = query.where(FindingORM.scanner == scanner)
    levels = _severity_clause(severity)
    if levels:
        query = query.where(FindingORM.severity.in_(levels))
    if verdict:
        query = query.where(FindingORM.triage_verdict == verdict)
    return query


class TriageFeedback(BaseModel):
    verdict: str
    reason: str | None = None


class FindingsListResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    items: list[dict[str, Any]] = Field(default_factory=list)
    total: int = 0
    page: int = 1
    per_page: int = 20


class TriageFeedbackResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    ok: bool = True
    finding: dict[str, Any] = Field(default_factory=dict)


class FindingCreate(BaseModel):
    """A finding published by an external producer (a plugin, the premium UI).

    The ten obligatory fields are exactly the ones ``Finding`` has no default
    for; ``timestamp``, ``extra`` and ``request_data`` are optional. Unknown
    fields are rejected (``extra="forbid"``) so a typo cannot slip into the
    session database as a silently ignored column.
    """

    model_config = ConfigDict(extra="forbid")

    scanner: str = Field(min_length=1, max_length=255)
    url: str = Field(min_length=1, max_length=MAX_URL_CHARS)
    method: str = Field(min_length=1, max_length=10)
    param_name: str = Field(min_length=1, max_length=255)
    param_location: str = Field(min_length=1, max_length=50)
    technique: str
    severity: Literal["low", "medium", "high", "critical"]
    confidence: Literal["tentative", "inferred", "confirmed"]
    payload: str = Field(max_length=MAX_EVIDENCE_CHARS)
    evidence: str = Field(max_length=MAX_EVIDENCE_CHARS)
    timestamp: datetime | None = None
    extra: dict[str, Any] = Field(default_factory=dict)
    request_data: dict[str, Any] | None = None

    @field_validator("method")
    @classmethod
    def _upper_method(cls, value: str) -> str:
        """Normalise the HTTP method: ``get`` and ``GET`` are the same finding."""
        return value.upper()

    @field_validator("extra", "request_data")
    @classmethod
    def _bounded_json(cls, value: dict[str, Any] | None) -> dict[str, Any] | None:
        """Reject oversized JSON blobs (serialised size, not character count)."""
        if value is None:
            return value
        size = len(json.dumps(value, default=str, ensure_ascii=False).encode("utf-8"))
        if size > MAX_JSON_BYTES:
            raise ValueError(f"serialised JSON is {size} bytes (max {MAX_JSON_BYTES})")
        return value


class FindingCreateResponse(BaseModel):
    model_config = ConfigDict(extra="allow")

    id: int
    scanner: str
    session_id: str


def _known_scanner_names(request: Request) -> set[str]:
    """Plugin names the catalog knows (built-in or installed, enabled or not).

    ``scanner`` is the key the UI and the reports filter and group by, so an
    unknown name would create a column nobody can filter (D9). The live loader
    is preferred; a fresh catalog covers the endpoint being hit before the
    loader has discovered anything and the tests that run without one.
    """
    loader = getattr(request.app.state, "plugin_loader", None)
    names = {record.name for record in loader.catalog()} if loader is not None else set()
    if not names:
        from pwnproxy.plugins.core.catalog import discover_plugins

        names = {record.name for record in discover_plugins()}
    return names


@router.post(
    "/findings",
    response_model=FindingCreateResponse,
    status_code=201,
    summary="Publish a finding from an external producer",
    responses={
        409: {"description": "No active session"},
        422: {"description": "Invalid body, or scanner not in the plugin catalog"},
        500: {"description": "The finding could not be stored; the body is the fixed detail 'could not save finding' (nothing is published)"},
    },
)
async def create_finding(payload: FindingCreate, request: Request):
    """Publish a finding from an external producer.

    Same path as an internal scanner finding: ``FindingStorage.save`` persists
    the row (which fires the triage callback) and only **after** a successful
    save the row is announced on the ``finding.stored`` channel — the one
    ``/ws/findings`` and ``/ws/events`` forward — and, for plugins that declare
    ``consumes=["finding"]``, on the raw ``finding`` channel as before.

    ``scanner`` must be a name in the plugin catalog (``422`` otherwise, with a
    pointer to ``GET /api/v1/plugins``); no active session is a ``409`` (writing
    into the default ``~/.pwnproxy/scanner_results.db`` would leave a file with
    no owner); a storage failure is a ``500`` with a fixed message (the
    exception goes to the log only) and publishes nothing.

    There is **no deduplication**: two identical POSTs create two rows.

    Security: the whole API has no authentication. It binds to ``127.0.0.1`` by
    default; exposing it outside the machine turns this endpoint into a way to
    inject findings. Body and catalog validation reduce garbage, they are not
    access control.
    """
    session_manager = getattr(request.app.state, "session_manager", None)
    session_id = getattr(session_manager, "active_name", None) if session_manager is not None else None
    if not session_id:
        raise HTTPException(status_code=409, detail="no active session")

    if payload.scanner not in _known_scanner_names(request):
        raise HTTPException(
            status_code=422,
            detail=(
                f"unknown scanner '{payload.scanner}': it is not in the plugin catalog "
                "(see GET /api/v1/plugins)"
            ),
        )

    from pwnproxy.plugins.core.base import Finding
    from pwnproxy.shared.findings.storage import FindingStorage

    finding = Finding(
        scanner=payload.scanner,
        url=payload.url,
        method=payload.method,
        param_name=payload.param_name,
        param_location=payload.param_location,
        technique=payload.technique,
        severity=payload.severity,
        confidence=payload.confidence,
        payload=payload.payload,
        evidence=payload.evidence,
        timestamp=payload.timestamp or datetime.now(UTC),
        extra=dict(payload.extra or {}),
        request_data=payload.request_data,
    )

    storage = FindingStorage(session_manager.get_scanner_engine())
    try:
        finding_id = await storage.save(finding)
    except Exception as exc:  # storage is the boundary: no row, no event, 500
        logger.warning("could not persist finding from '%s': %s", payload.scanner, exc)
        raise HTTPException(status_code=500, detail="could not save finding") from exc

    row = await storage.get(finding_id)
    if row is None:  # saved but unreadable: announce what we know, never fail
        logger.warning("saved finding %s could not be re-read; announcing a partial row", finding_id)
        row = {"id": finding_id, "scanner": finding.scanner, "url": finding.url}

    hook_bus = getattr(request.app.state, "hook_bus", None)
    if hook_bus is not None:
        # Raw channel (historical contract): plugins with ``consumes=["finding"]``
        # receive the stored row, and the loader's storage consumer skips it
        # because it already carries ``id`` (no second row).
        try:
            hook_bus.publish("finding", {**row, "session_id": session_id})
        except Exception:  # a dead subscriber must not fail a persisted finding
            logger.debug("could not publish the finding event", exc_info=True)
    # Stored channel: the only one the WebSocket relays read, so the UI gets the
    # row exactly once even when no plugin consumes findings.
    publish_stored_finding(hook_bus, row, session_id)

    return {"id": finding_id, "scanner": payload.scanner, "session_id": session_id}


@router.patch("/findings/{finding_id}/feedback", response_model=TriageFeedbackResponse)
async def triage_feedback(finding_id: int, payload: TriageFeedback, request: Request):
    """Human triage verdict: overwrites any automatic one (method=human) + history row."""
    if payload.verdict not in VALID_TRIAGE_VERDICTS:
        raise HTTPException(status_code=422, detail=f"verdict must be one of {VALID_TRIAGE_VERDICTS}")
    pipeline = getattr(request.app.state, "triage_pipeline", None)
    try:
        if pipeline is not None:
            updated = await pipeline.handle_human_feedback(finding_id, payload.verdict, payload.reason)
        else:
            from pwnproxy.shared.findings.storage import FindingStorage
            updated = await FindingStorage(request.app.state.session_manager.get_scanner_engine()).set_triage(
                finding_id, verdict=payload.verdict, method="human",
                score=None, reason=payload.reason or "human_review",
            )
    except Exception as exc:
        logger.warning("triage feedback failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    if updated is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    # Publish only when no pipeline handled it: TriagePipeline._set already
    # emits triage.updated on the same hook_bus (avoid duplicate WS events).
    if pipeline is None or getattr(pipeline, "hook_bus", None) is None:
        hook_bus = request.app.state.hook_bus
        if hook_bus:
            try:
                triage_payload: dict = {
                    "finding_id": finding_id,
                    "verdict": payload.verdict,
                    "method": "human",
                    "score": updated.get("triage_score"),
                    "reason": updated.get("triage_reason"),
                }
                sm = getattr(request.app.state, "session_manager", None)
                sid = getattr(sm, "active_name", None) if sm else None
                if sid:
                    triage_payload["session_id"] = sid
                hook_bus.publish("triage.updated", triage_payload)
            except Exception:
                logger.debug("could not publish triage.updated", exc_info=True)
    return {"ok": True, "finding": updated}


async def _export_lines(storage):
    async for row in storage.iter_all():
        features = {}
        extra = row.get("extra") or {}
        if isinstance(extra, dict):
            features = extra.get("triage_features") or {}
        yield json.dumps({
            "id": row.get("id"),
            "scanner": row.get("scanner"),
            "url": row.get("url"),
            "method": row.get("method"),
            "param_name": row.get("param_name"),
            "param_location": row.get("param_location"),
            "technique": row.get("technique"),
            "severity": row.get("severity"),
            "confidence": row.get("confidence"),
            "payload": row.get("payload"),
            "evidence": row.get("evidence"),
            "triage_score": row.get("triage_score"),
            "triage_verdict": row.get("triage_verdict"),
            "triage_method": row.get("triage_method"),
            "triage_reason": row.get("triage_reason"),
            "ground_truth": row.get("triage_verdict") if row.get("triage_method") == "human" else None,
            "features": features,
        }, default=str) + "\n"


@router.get("/findings/export-triage")
async def export_triage(request: Request, format: str = Query("jsonl", description="Export format (jsonl)")):
    """Stream every finding + full triage state as JSONL (training dataset)."""
    if format != "jsonl":
        raise HTTPException(status_code=422, detail="unsupported format (only 'jsonl')")
    from pwnproxy.shared.findings.storage import FindingStorage
    storage = FindingStorage(request.app.state.session_manager.get_scanner_engine())
    return StreamingResponse(
        _export_lines(storage),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": 'attachment; filename="triage-dataset.jsonl"'},
    )


@router.get("/findings/{scanner_name}", response_model=FindingsListResponse)
async def get_findings(
    scanner_name: str,
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=500),
    severity: str | None = Query(None, description="Comma-separated severity levels"),
    verdict: str | None = Query(None, description="Triage verdict filter (true_positive|false_positive|uncertain)"),
):
    offset = (page - 1) * per_page
    engine = request.app.state.session_manager.get_scanner_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        try:
            count_q = _apply_filters(select(func.count(FindingORM.id)), scanner_name, severity, verdict)
            total = (await session.execute(count_q)).scalar() or 0

            sel_q = _apply_filters(select(FindingORM), scanner_name, severity, verdict)
            sel_q = sel_q.order_by(FindingORM.id.desc()).limit(per_page).offset(offset)
            result = await session.execute(sel_q)
            rows = result.scalars().all()
            items = [{c.name: getattr(r, c.name) for c in FindingORM.__table__.columns} for r in rows]
            return {"items": items, "total": total, "page": page, "per_page": per_page}
        except Exception as exc:
            logger.warning(f"Could not query findings: {exc}")
            return {"items": [], "total": 0, "page": page, "per_page": per_page}


@router.get("/findings", response_model=FindingsListResponse)
async def list_all_findings(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=500),
    severity: str | None = Query(None, description="Comma-separated severity levels"),
    verdict: str | None = Query(None, description="Triage verdict filter (true_positive|false_positive|uncertain)"),
):
    offset = (page - 1) * per_page
    engine = request.app.state.session_manager.get_scanner_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        try:
            count_q = _apply_filters(select(func.count(FindingORM.id)), severity=severity, verdict=verdict)
            total = (await session.execute(count_q)).scalar() or 0

            sel_q = _apply_filters(select(FindingORM), severity=severity, verdict=verdict)
            sel_q = sel_q.order_by(FindingORM.id.desc()).limit(per_page).offset(offset)
            result = await session.execute(sel_q)
            rows = result.scalars().all()
            items = [{c.name: getattr(r, c.name) for c in FindingORM.__table__.columns} for r in rows]
            return {"items": items, "total": total, "page": page, "per_page": per_page}
        except Exception as exc:
            logger.warning(f"Could not query findings: {exc}")
            return {"items": [], "total": 0, "page": page, "per_page": per_page}


@router.delete("/findings", status_code=204)
async def delete_all_findings(request: Request, ids: str = Query(None, description="Comma-separated finding IDs to delete (batch); empty deletes all")):
    engine = request.app.state.session_manager.get_scanner_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        try:
            if ids:
                id_list = [int(x.strip()) for x in ids.split(",") if x.strip()]
                if id_list:
                    await session.execute(FindingORM.__table__.delete().where(FindingORM.id.in_(id_list)))
            else:
                await session.execute(FindingORM.__table__.delete())
            await session.commit()
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=f"Invalid ids: {exc}") from exc
        except Exception as exc:
            logger.warning(f"Could not delete findings: {exc}")


@router.delete("/findings/{finding_id}", status_code=204)
async def delete_finding(finding_id: int, request: Request):
    engine = request.app.state.session_manager.get_scanner_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        try:
            result = await session.execute(select(FindingORM).where(FindingORM.id == finding_id))
            record = result.scalar_one_or_none()
            if not record:
                raise HTTPException(status_code=404, detail="Finding not found")
            await session.delete(record)
            await session.commit()
        except HTTPException:
            raise
        except Exception as exc:
            logger.warning(f"Could not delete finding: {exc}")
            raise HTTPException(status_code=500, detail=str(exc)) from exc
