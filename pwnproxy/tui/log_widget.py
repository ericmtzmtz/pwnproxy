from collections import deque
from typing import Optional

from textual.message import Message
from textual.widgets import DataTable
from textual.widgets._data_table import RowKey

STATUS_STYLES: dict[str, str] = {
    "2": "green",
    "3": "cyan",
    "4": "yellow",
    "5": "red",
}


def _color_status(code: Optional[int]) -> str:
    if code is None:
        return "---"
    s = str(code)
    color = STATUS_STYLES.get(s[:1], "white")
    return f"[{color}]{s}[/]"


MAX_LOG_ROWS = 5000


class LogTable(DataTable):
    class AddFlow(Message):
        def __init__(self, msg: dict) -> None:
            self.msg = msg
            super().__init__()

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._row_keys: deque[RowKey] = deque()
        self._can_focus = False

    def on_mount(self) -> None:
        self.add_columns("Method", "Status", "URL", "ID")
        self.cursor_type = "row"
        self.zebra_stripes = True

    def on_log_table_add_flow(self, event: AddFlow) -> None:
        data = event.msg
        method = data.get("method", "")
        url = data.get("url", "")
        status = str(data.get("status_code", ""))
        flow_id = str(data.get("id", ""))[:8]
        key = self.add_row(method, url, status, flow_id, height=1)
        self._row_keys.append(key)
        self._maybe_scroll()
        self._trim()

    def _maybe_scroll(self) -> None:
        self.scroll_end(animate=False)

    def _trim(self) -> None:
        while len(self._row_keys) > MAX_LOG_ROWS:
            oldest = self._row_keys.popleft()
            try:
                self.remove_row(oldest)
            except Exception:
                pass
