import json
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel
from sqlalchemy import select, func, delete
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from pwnproxy.shared.findings.storage import FindingORM

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1", tags=["findings"])

VALID_TRIAGE_VERDICTS = ("true_positive", "false_positive")


def _severity_clause(severity: Optional[str]) -> list:
    if not severity:
        return []
    return [s.strip() for s in severity.split(",") if s.strip()]


def _apply_filters(query, scanner: Optional[str] = None, severity: Optional[str] = None,
                   verdict: Optional[str] = None):
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
    reason: Optional[str] = None


@router.patch("/findings/{finding_id}/feedback")
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
        raise HTTPException(status_code=500, detail=str(exc))
    if updated is None:
        raise HTTPException(status_code=404, detail="Finding not found")
    # Publish only when no pipeline handled it: TriagePipeline._set already
    # emits triage.updated on the same hook_bus (avoid duplicate WS events).
    if pipeline is None or getattr(pipeline, "hook_bus", None) is None:
        hook_bus = request.app.state.hook_bus
        if hook_bus:
            try:
                hook_bus.publish("triage.updated", {
                    "finding_id": finding_id,
                    "verdict": payload.verdict,
                    "method": "human",
                    "score": updated.get("triage_score"),
                    "reason": updated.get("triage_reason"),
                })
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


@router.get("/findings/{scanner_name}")
async def get_findings(
    scanner_name: str,
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=500),
    severity: Optional[str] = Query(None, description="Comma-separated severity levels"),
    verdict: Optional[str] = Query(None, description="Triage verdict filter (true_positive|false_positive|uncertain)"),
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


@router.get("/findings")
async def list_all_findings(
    request: Request,
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=500),
    severity: Optional[str] = Query(None, description="Comma-separated severity levels"),
    verdict: Optional[str] = Query(None, description="Triage verdict filter (true_positive|false_positive|uncertain)"),
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
async def delete_all_findings(request: Request):
    engine = request.app.state.session_manager.get_scanner_engine()
    factory = sessionmaker(engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        try:
            await session.execute(FindingORM.__table__.delete())
            await session.commit()
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
            raise HTTPException(status_code=500, detail=str(exc))
