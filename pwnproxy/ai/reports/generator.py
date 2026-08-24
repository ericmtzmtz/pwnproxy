"""Phase 2 + 3: orchestrate analysis -> writing -> rendering into artifacts."""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable, Optional

from pydantic import BaseModel, Field

from pwnproxy.ai.llm.client import LLMClient
from pwnproxy.ai.llm.models import LLMMessage, LLMRequest
from pwnproxy.ai.reports import analyzer
from pwnproxy.ai.reports.render import render_html, render_markdown, render_pdf

logger = logging.getLogger(__name__)

AUDIENCES = ("executive", "technical", "remediation")
FORMATS = ("md", "html", "pdf")
MAX_NARRATIVE_GROUPS = 25
ProgressFn = Callable[[str, int], Awaitable[None]]


class GroupNarrative(BaseModel):
    title: str = Field(description="Location-aware title for the finding")
    description: str = Field(description="How the vulnerability triggers, grounded in facts")
    impact_paragraph: str = Field(description="Business/technical impact grounded in facts.impact")
    remediation_steps: list[str] = Field(description="Ordered concrete fix actions")


class ReportGenerator:
    def __init__(self, llm: LLMClient, session_name: str = "") -> None:
        self._llm = llm
        self._session_name = session_name or "default"

    async def generate(
        self,
        findings: list[dict],
        out_dir: Path,
        audience: str = "technical",
        formats: tuple[str, ...] | list[str] = ("md",),
        progress: Optional[ProgressFn] = None,
    ) -> dict[str, Any]:
        if not findings:
            raise ValueError(
                "No findings in the current session: run a scan first before generating a report"
            )
        if audience not in AUDIENCES:
            raise ValueError(f"Unknown audience '{audience}'. Valid: {', '.join(AUDIENCES)}")
        bad_formats = [f for f in formats if f not in FORMATS]
        if bad_formats:
            raise ValueError(f"Unknown format(s): {', '.join(bad_formats)}. Valid: md, html, pdf")

        async def _notify(phase: str, pct: int) -> None:
            if progress:
                await progress(phase, pct)

        # ---- Phase 1: analysis -------------------------------------------------
        groups = analyzer.dedup_findings(findings)
        aggregates = analyzer.risk_aggregates(groups, raw_count=len(findings))
        await _notify("analyzing", 5)
        await analyzer.extract_group_facts(
            self._llm,
            groups,
            progress=lambda done, total: _notify("analyzing", 5 + int(done / max(total, 1) * 35)),
        )
        flagged_groups = [g for g in groups if g.get("flagged")]

        # ---- Phase 2: writing --------------------------------------------------
        await _notify("writing", 45)
        narratives = await self._write_narratives(groups, audience, _notify)
        exec_summary = await self._write_exec_summary(groups, aggregates, _notify)

        # ---- Phase 3: rendering ------------------------------------------------
        await _notify("rendering", 88)
        context = self._build_context(aggregates, groups, narratives, exec_summary, audience)
        out_dir.mkdir(parents=True, exist_ok=True)
        files = self._render_artifacts(context, out_dir, formats)
        await _notify("rendering", 100)

        return {
            "files": files,
            "aggregates": aggregates,
            "flagged_groups": len(flagged_groups),
            "audience": audience,
            "session": self._session_name,
        }

    async def _write_narratives(self, groups: list[dict], audience: str, notify: ProgressFn) -> list[GroupNarrative]:
        system = analyzer._prompt(f"narrative_{audience}.txt")
        corpus_by_id = [self._corpus(g) for g in groups]
        narratives: list[GroupNarrative] = []
        writable = groups[:MAX_NARRATIVE_GROUPS]
        for i, group in enumerate(writable):
            request = LLMRequest(
                messages=[
                    LLMMessage(role="system", content=system),
                    LLMMessage(role="user", content=json.dumps(group["facts"], ensure_ascii=False)),
                ],
            )
            narrative, _resp = await self._llm.generate_structured(request, GroupNarrative)
            data = narrative.model_dump()
            data = self._sanitize_narrative(data, corpus_by_id[i])
            narratives.append(GroupNarrative(**data))
            pct = 45 + int((i + 1) / len(writable) * 35)
            await notify("writing", pct)
        for group in groups[MAX_NARRATIVE_GROUPS:]:
            facts = group.get("facts", {})
            narratives.append(GroupNarrative(
                title=facts.get("title") or group.get("technique") or "Finding",
                description=facts.get("vector") or "",
                impact_paragraph=facts.get("impact") or "",
                remediation_steps=[facts.get("remediation")] if facts.get("remediation") else [],
            ))
        return narratives

    async def _write_exec_summary(self, groups: list[dict], aggregates: dict, notify: ProgressFn) -> str:
        highlights: list[str] = []
        chunks = analyzer.chunk(groups)
        if len(chunks) > 1:
            system = analyzer._prompt("summary.txt")
            for c in chunks:
                bullets = "\n".join(
                    f"- [{g['facts'].get('severity')}] {g['facts'].get('title')} ({g['url']})"
                    for g in c
                )
                request = LLMRequest(
                    messages=[
                        LLMMessage(role="system", content=system),
                        LLMMessage(role="user", content=bullets),
                    ],
                    json_mode=True,
                )
                summary, _resp = await self._llm.generate_structured(request, analyzer.ChunkSummary)
                highlights.extend(summary.highlights[:4])
        else:
            highlights = [
                f"[{g['facts'].get('severity')}] {g['facts'].get('title')} ({g['url']})"
                for g in groups[:10]
            ]
        user_content = (
            json.dumps(aggregates, ensure_ascii=False)
            + "\n\nHighlights:\n"
            + "\n".join(highlights[:20])
        )
        request = LLMRequest(messages=[
            LLMMessage(role="system", content=analyzer._prompt("summary.txt")),
            LLMMessage(role="user", content=user_content),
        ])
        response = await self._llm.generate(request)
        return response.text.strip()

    @staticmethod
    def _corpus(group: dict) -> str:
        parts = [group.get("evidence") or "", group.get("url") or "", *group.get("payloads", []),
                 group.get("technique") or ""]
        return "\n".join(parts)

    @staticmethod
    def _sanitize_narrative(data: dict, corpus: str) -> dict:
        for key, value in data.items():
            if isinstance(value, str):
                data[key], _removed = analyzer.strip_untraceable_cves(value, corpus)
            elif isinstance(value, list):
                cleaned = []
                removed_any = False
                for item in value:
                    item, removed = analyzer.strip_untraceable_cves(str(item), corpus)
                    removed_any = removed_any or removed
                    cleaned.append(item)
                data[key] = cleaned
        return data

    def _build_context(
        self,
        aggregates: dict,
        groups: list[dict],
        narratives: list[GroupNarrative],
        exec_summary: str,
        audience: str,
    ) -> dict:
        sections = []
        for group, narrative in zip(groups, narratives):
            request_data = group.get("request_data")
            sections.append({
                "url": group.get("url"),
                "method": group.get("method"),
                "param_name": group.get("param_name"),
                "param_location": group.get("param_location"),
                "technique": group.get("technique"),
                "confidence": group.get("confidence"),
                "severity": (group.get("severity") or "info").lower(),
                "scanner": group.get("scanner"),
                "occurrences": group.get("occurrences", 1),
                "payloads": group.get("payloads", []),
                "flagged": bool(group.get("flagged")),
                "evidence": (group.get("evidence") or "")[:4000],
                "request_data_json": (
                    json.dumps(request_data, indent=2, default=str)[:4000] if request_data else ""
                ),
                "narrative": narrative,
            })
        sections.sort(key=lambda s: analyzer.SEVERITY_ORDER.get(s["severity"], 99))
        by_severity: dict[str, list[dict]] = {}
        for s in sections:
            by_severity.setdefault(s["severity"], []).append(s)
        return {
            "title": "Security Assessment Report",
            "subtitle": f"Session: {self._session_name}",
            "session": self._session_name,
            "audience": audience,
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "flagged_count": sum(1 for s in sections if s["flagged"]),
            "summary": aggregates,
            "exec_summary": exec_summary,
            "sections": sections,
            "sections_by_severity": by_severity,
            "severity_order": ("critical", "high", "medium", "low", "info"),
        }

    @staticmethod
    def _render_artifacts(context: dict, out_dir: Path, formats) -> dict[str, str]:
        markdown_text = render_markdown(context)
        files: dict[str, str] = {}
        if "md" in formats:
            (out_dir / "report.md").write_text(markdown_text, encoding="utf-8")
            files["md"] = "report.md"
        if "html" in formats:
            html_text = render_html(context, markdown_text)
            (out_dir / "report.html").write_text(html_text, encoding="utf-8")
            files["html"] = "report.html"
        if "pdf" in formats:
            html_text = render_html(context, markdown_text)
            render_pdf(html_text, out_dir / "report.pdf")
            files["pdf"] = "report.pdf"
        return files
