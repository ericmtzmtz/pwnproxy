from collections import deque
from datetime import datetime
from typing import Optional

from textual.message import Message
from textual.widgets import DataTable
from textual.widgets._data_table import RowKey

MAX_SESSION_ROWS = 5000


class SessionsTable(DataTable):
    class LoadSessions(Message):
        def __init__(self, data: list[dict]) -> None:
            self.data = data
            super().__init__()

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._row_keys: deque[RowKey] = deque()
        self._can_focus = False

    def on_mount(self) -> None:
        self.add_columns("Type", "Status", "Label", "Source URL", "Refs", "Last Seen")
        self.cursor_type = "row"
        self.zebra_stripes = True

    def on_sessions_table_load_sessions(self, event: LoadSessions) -> None:
        self.clear()
        self._row_keys.clear()
        for s in event.data:
            label = s.get("label") or ""
            source = (s.get("source_url") or "")[:60]
            refs = str(s.get("ref_count", ""))
            last = ""
            if ls := s.get("last_seen"):
                try:
                    dt = datetime.fromisoformat(ls)
                    last = dt.strftime("%H:%M:%S")
                except Exception:
                    last = ls[:19]
            key = self.add_row(
                s.get("token_type", ""),
                s.get("status", ""),
                label,
                source,
                refs,
                last,
                height=1,
            )
            self._row_keys.append(key)
        self._trim()

    def _trim(self) -> None:
        while len(self._row_keys) > MAX_SESSION_ROWS:
            oldest = self._row_keys.popleft()
            try:
                self.remove_row(oldest)
            except Exception:
                pass
