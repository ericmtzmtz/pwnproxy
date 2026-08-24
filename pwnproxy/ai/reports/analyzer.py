"""Phase 1: load findings, deduplicate, extract structured facts via the LLM.

The analyzer never lets the LLM see raw findings without grounding rules:
every fact must be traceable to fields present in the source finding.
"""
from __future__ import annotations

import logging
import re
from collections import Counter
from typing import Awaitable, Callable, Iterable, Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from pwnproxy.ai.llm.client import LLMClient
from pwnproxy.ai.llm.models import LLMMessage, LLMRequest

logger = logging.getLogger(__name__)

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

CHUNK_SIZE = 8
PROMPTS_DIR = __package__ + ".prompts"


class GroupFacts(BaseModel):
    title: str = Field(description="Short descriptive title for the finding group")
    severity: str = Field(description="One of: critical, high, medium, low, info")
    vector: str = Field(description="How the vulnerability is triggered, grounded in evidence")
    key_evidence: str = Field(description="Verbatim snippet copied from the finding evidence")
    impact: str = Field(description="Concrete impact, only what follows from the evidence")
    remediation: str = Field(description="How to fix, grounded in the vulnerability class")


class ChunkSummary(BaseModel):
    highlights: list[str] = Field(description="One-line summaries of the most relevant findings in the chunk")


def _prompt(name: str) -> str:
    from importlib.resources import files

    return files(PROMPTS_DIR).joinpath(name).read_text(encoding="utf-8")


def dedup_findings(findings: list[dict]) -> list[dict]:
    """Collapse findings sharing (url, technique, param_name) into one entry.

    Payloads are consolidated into a list; occurrences are counted; the worst
    severity wins. Order of first appearance is preserved.
    """
    groups: dict[tuple[str, str, str], dict] = {}
    for f in findings:
        key = (
            f.get("url") or "",
            f.get("technique") or "",
            f.get("param_name") or "",
        )
        existing = groups.get(key)
        if existing is None:
            g = dict(f)
            g["payloads"] = [f["payload"]] if f.get("payload") else []
            g["occurrences"] = 1
            groups[key] = g
        else:
            payload = f.get("payload") or ""
            if payload and payload not in existing["payloads"]:
                existing["payloads"].append(payload)
            existing["occurrences"] += 1
            if _severity_rank(f.get("severity")) < _severity_rank(existing.get("severity")):
                existing["severity"] = f.get("severity")
            if f.get("confidence") == "confirmed":
                existing["confidence"] = "confirmed"
    return list(groups.values())


def _severity_rank(severity: Optional[str]) -> int:
    return SEVERITY_ORDER.get((severity or "").lower(), len(SEVERITY_ORDER))


def risk_aggregates(groups: list[dict], raw_count: int) -> dict:
    """Aggregate posture metrics for the executive summary."""
    by_severity = Counter((g.get("severity") or "info").lower() for g in groups)
    hosts = {urlparse(g.get("url") or "").netloc for g in groups}
    hosts.discard("")
    scanners = Counter(g.get("scanner") or "unknown" for g in groups)
    confirmed = sum(1 for g in groups if g.get("confidence") == "confirmed")
    max_severity = None
    for sev in ("critical", "high", "medium", "low", "info"):
        if by_severity.get(sev):
            max_severity = sev
            break
    return {
        "raw_findings": raw_count,
        "deduplicated_groups": len(groups),
        "by_severity": {sev: by_severity[sev] for sev in SEVERITY_ORDER if by_severity.get(sev)},
        "affected_hosts": sorted(hosts),
        "scanners": dict(scanners),
        "confirmed": confirmed,
        "max_severity": max_severity,
    }


def chunk(items: list, size: int = CHUNK_SIZE) -> list[list]:
    return [items[i : i + size] for i in range(0, len(items), size)]


_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def strip_untraceable_cves(text: str, corpus: str) -> tuple[str, bool]:
    """Remove CVE identifiers from ``text`` that are absent from ``corpus``.

    Returns (clean_text, removed_something).
    """
    untraceable = {
        cve for cve in _CVE_RE.findall(text)
        if cve.lower() not in corpus.lower()
    }
    removed = False
    for cve in untraceable:
        text = text.replace(cve, "[unverified reference removed]")
        removed = True
    return text, removed


def sanitize_facts(facts: dict, group: dict) -> tuple[dict, bool]:
    """Strip CVE identifiers that cannot be traced to the source finding.

    Returns (sanitized_facts, flagged). Flagged means at least one invented
    reference was removed; the report marks such groups as unverified.
    """
    corpus_parts = [group.get("evidence") or "", group.get("url") or "", *group.get("payloads", []),
                    group.get("technique") or ""]
    corpus = "\n".join(corpus_parts)
    flagged = False
    sanitized = {}
    for key, value in facts.items():
        if isinstance(value, str):
            value, removed = strip_untraceable_cves(value, corpus)
            flagged = flagged or removed
        sanitized[key] = value
    return sanitized, flagged


def _finding_context(group: dict) -> str:
    payloads = "\n".join(f"- {p}" for p in group.get("payloads", [])) or "-"
    request_data = group.get("request_data")
    req_block = ""
    if request_data:
        try:
            import json

            req_block = "\nrequest_data:\n" + json.dumps(request_data)[:2000]
        except Exception:
            pass
    return (
        f"url: {group.get('url')}\n"
        f"method: {group.get('method')}\n"
        f"scanner: {group.get('scanner')}\n"
        f"technique: {group.get('technique')}\n"
        f"param: {group.get('param_name')} ({group.get('param_location')})\n"
        f"severity: {group.get('severity')}\n"
        f"confidence: {group.get('confidence')}\n"
        f"payloads:\n{payloads}"
        f"\nevidence:\n{(group.get('evidence') or '')[:4000]}"
        f"{req_block}"
    )


async def extract_group_facts(
    llm: LLMClient,
    groups: list[dict],
    progress: Optional[Callable[[int, int], Awaitable[None]]] = None,
) -> None:
    """Populate ``facts`` on each group in place using structured LLM output.

    CVE references not traceable to the source finding are stripped and the
    group is flagged so the renderer can mark it.
    """
    system = _prompt("facts.txt")
    done = 0
    for group in groups:
        request = LLMRequest(
            messages=[
                LLMMessage(role="system", content=system),
                LLMMessage(role="user", content=_finding_context(group)),
            ],
            json_mode=True,
        )
        facts, _response = await llm.generate_structured(request, GroupFacts)
        data = facts.model_dump()
        data, flagged = sanitize_facts(data, group)
        group["facts"] = data
        group["flagged"] = flagged
        done += 1
        if progress:
            await progress(done, len(groups))
