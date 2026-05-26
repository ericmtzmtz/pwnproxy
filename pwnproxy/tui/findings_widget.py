from collections import deque
from typing import Optional

from textual.message import Message
from textual.widgets import DataTable
from textual.widgets._data_table import RowKey

SEVERITY_STYLES: dict[str, str] = {
    "critical": "red",
    "high": "orange3",
    "medium": "yellow",
    "low": "cyan",
    "info": "blue",
}

MAX_FINDING_ROWS = 5000


def _color_severity(severity: Optional[str]) -> str:
    s = (severity or "info").lower()
    color = SEVERITY_STYLES.get(s, "white")
    return f"[{color}]{s.upper()}[/]"


class FindingsTable(DataTable):
    DEFAULT_CSS = """
    FindingsTable { height: 1fr; }
    """
    class AddFinding(Message):
        def __init__(self, msg: dict) -> None:
            self.msg = msg
            super().__init__()

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._row_keys: deque[RowKey] = deque()
        self._can_focus = False

    def on_mount(self) -> None:
        self.add_columns("Scanner", "Target", "Severity", "Detail")

    def on_findings_table_add_finding(self, event: AddFinding) -> None:
        data = event.msg
        scanner = data.get("scanner", "?").upper()
        target = data.get("target_url") or data.get("url", "")
        severity = _color_severity(data.get("severity"))
        detail = str(data.get("detail", "") or "")
        if len(detail) > 80:
            detail = detail[:77] + "..."
        key = self.add_row(scanner, target, severity, detail, height=1)
        self._row_keys.append(key)
        self.scroll_end(animate=False)
        self._trim()

    def _trim(self) -> None:
        while len(self._row_keys) > MAX_FINDING_ROWS:
            oldest = self._row_keys.popleft()
            try:
                self.remove_row(oldest)
            except Exception:
                pass
