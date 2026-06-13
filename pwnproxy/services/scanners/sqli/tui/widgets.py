from textual.widgets import Static


class SeverityBadge(Static):
    def __init__(self, severity: str, confidence: str):
        if severity == "high" and confidence == "confirmed":
            icon = "🔴"
        elif severity == "medium" or confidence == "tentative":
            icon = "🟡"
        else:
            icon = "⚪"
        super().__init__(f" {icon} ", classes=f"severity-{severity}")


class EvidenceViewer(Static):
    def __init__(self, evidence: str = ""):
        super().__init__(evidence or "No evidence", classes="evidence-viewer")
