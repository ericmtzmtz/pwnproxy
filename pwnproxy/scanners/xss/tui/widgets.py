from typing import Optional

from textual.widgets import Static


class ContextBadge(Static):
    def __init__(self, context: str):
        icons = {
            "html_body": "🌐",
            "html_attr": "🔗",
            "js_string": "📜",
            "url": "🔗",
        }
        icon = icons.get(context, "❓")
        super().__init__(f" {icon} {context} ", classes=f"context-{context}")


class EvidenceViewer(Static):
    def __init__(self, evidence: Optional[str] = ""):
        super().__init__(evidence or "No evidence", classes="evidence-viewer")
