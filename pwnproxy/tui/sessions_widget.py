from typing import Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, DataTable


class SessionsTab(Vertical):
    DEFAULT_CSS = """
    SessionsTab {
        height: 1fr;
    }
    #session-controls {
        height: auto;
        padding: 0;
        align: center middle;
    }
    .sessions-col {
        height: auto;
        align: center middle;
    }
    .sessions-col Button {
        width: 14;
        height: 3;
        margin: 0 1;
    }
    SessionsTable {
        height: 1fr;
    }
    """

    def compose(self) -> ComposeResult:
        with Horizontal(id="session-controls"):
            with Vertical(classes="sessions-col"):
                yield Button("New Session", id="btn-session-new", variant="primary")
                yield Button("Load", id="btn-session-load")
            with Vertical(classes="sessions-col"):
                yield Button("Rename", id="btn-session-rename")
                yield Button("Save", id="btn-session-save")
            with Vertical(classes="sessions-col"):
                yield Button("Delete", id="btn-session-delete", variant="error")
        yield SessionsTable(id="sessions-table")


class SessionsTable(DataTable):
    DEFAULT_CSS = """
    SessionsTable { height: 1fr; }
    """
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
