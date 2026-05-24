from typing import Optional

from textual.message import Message
from textual.widgets import DataTable


class SessionsTable(DataTable):
    class LoadSessions(Message):
        def __init__(self, data: list[dict]) -> None:
            self.data = data
            super().__init__()

    class SessionCreated(Message):
        def __init__(self, name: str) -> None:
            self.name = name
            super().__init__()

    class SessionLoaded(Message):
        def __init__(self, name: str) -> None:
            self.name = name
            super().__init__()

    class SessionSaved(Message):
        def __init__(self, name: str) -> None:
            self.name = name
            super().__init__()

    class SessionDeleted(Message):
        def __init__(self, name: str) -> None:
            self.name = name
            super().__init__()

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        self._active_name: str = "default"

    def on_mount(self) -> None:
        self.add_columns("Name", "Created", "Last Modified", "Active")
        self.cursor_type = "row"
        self.zebra_stripes = True

    def set_active(self, name: str) -> None:
        self._active_name = name

    def on_sessions_table_load_sessions(self, event: LoadSessions) -> None:
        self.clear()
        self.add_columns("Name", "Created", "Last Modified", "Active")
        for s in event.data:
            created = (s.get("created_at") or "")[:19]
            modified = (s.get("last_modified") or "")[:19]
            active = "[green]Active[/]" if s.get("active") else ""
            self.add_row(
                s["name"],
                created,
                modified,
                active,
                height=1,
            )
        if event.data:
            self._active_name = next(
                (s["name"] for s in event.data if s.get("active")),
                event.data[0]["name"],
            )

    def on_sessions_table_session_created(self, event: SessionCreated) -> None:
        self._active_name = event.name

    def on_sessions_table_session_loaded(self, event: SessionLoaded) -> None:
        self._active_name = event.name

    def on_sessions_table_session_saved(self, event: SessionSaved) -> None:
        pass

    def on_sessions_table_session_deleted(self, event: SessionDeleted) -> None:
        pass

    def get_selected_name(self) -> Optional[str]:
        idx = self.cursor_row
        if idx is None:
            return None
        row = self.get_row_at(idx)
        return str(row[0]) if row else None
