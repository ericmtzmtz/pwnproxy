import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Optional

from jinja2 import Environment, PackageLoader, select_autoescape

from pwnproxy.plugins.core.base import Finding

logger = logging.getLogger(__name__)

_env: Optional[Environment] = None


def _get_env() -> Environment:
    global _env
    if _env is None:
        _env = Environment(
            loader=PackageLoader("pwnproxy.export", "templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )
    return _env


class ExportEngine:
    def __init__(self, findings: list[Finding], target_url: str = "", scanners: Optional[list[str]] = None):
        self.findings = findings
        self.target_url = target_url
        self.scanners = scanners or list({f.scanner for f in findings})

    def to_dicts(self) -> list[dict]:
        return [_finding_to_dict(f) for f in self.findings]

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dicts(), indent=indent, default=str)

    def to_sarif(self, indent: int = 2) -> str:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "pwnproxy",
                            "version": "0.1.0",
                            "informationUri": "",
                        }
                    },
                    "results": [
                        {
                            "ruleId": f"{f.scanner}/{f.technique}",
                            "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(
                                f.severity.lower(), "none"
                            ),
                            "message": {"text": f"{f.technique} via {f.param_name}"},
                            "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.url}}}],
                            "properties": {"payload": f.payload, "evidence": f.evidence},
                        }
                        for f in self.findings
                    ],
                }
            ],
        }
        return json.dumps(sarif, indent=indent, default=str)

    def to_html(self) -> str:
        env = _get_env()
        template = env.get_template("report.html")
        return template.render(
            findings=self.to_dicts(),
            target_url=self.target_url,
            scanners=self.scanners,
            generated_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC"),
            version="0.1.0",
        )

    def to_pdf(self, output_path: Optional[str] = None) -> Optional[str]:
        html = self.to_html()
        try:
            import weasyprint
        except ImportError:
            logger.warning("weasyprint not installed; saving HTML instead")
            if output_path:
                out = output_path.rsplit(".", 1)[0] + ".html"
                Path(out).write_text(html, encoding="utf-8")
                logger.info("HTML report written to %s (install weasyprint for PDF)", out)
                return out
            return None

        if output_path:
            weasyprint.HTML(string=html).write_pdf(output_path)
            logger.info("PDF report written to %s", output_path)
            return output_path
        return html

    def write(self, fmt: str, output_path: Optional[str] = None) -> Optional[str]:
        if fmt == "json":
            content = self.to_json()
        elif fmt == "sarif":
            content = self.to_sarif()
        elif fmt == "html":
            content = self.to_html()
        elif fmt == "pdf":
            return self.to_pdf(output_path)
        else:
            raise ValueError(f"Unknown format: {fmt}")

        if output_path:
            Path(output_path).write_text(content, encoding="utf-8")
            logger.info("%s report written to %s", fmt.upper(), output_path)
            return output_path
        return content


def _finding_to_dict(f: Finding) -> dict:
    return {
        "scanner": f.scanner,
        "url": f.url,
        "method": f.method,
        "param_name": f.param_name,
        "param_location": f.param_location,
        "technique": f.technique,
        "severity": f.severity,
        "confidence": f.confidence,
        "payload": f.payload,
        "evidence": f.evidence,
        "timestamp": f.timestamp.isoformat() if hasattr(f.timestamp, "isoformat") else f.timestamp,
        "request_data": getattr(f, "request_data", None),
    }
