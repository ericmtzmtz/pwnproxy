from datetime import datetime
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Label

from pwnproxy.core.models import Flow
from pwnproxy.repeater.integration import format_flow_as_raw_request
from pwnproxy.repeater.tui.tab import RepeaterTab
from pwnproxy.repeater.tui.viewer import ResponseViewer


class RepeaterTable(DataTable):
    def on_mount(self) -> None:
        self.add_columns("Method", "URL", "Time", "Status")
        self.cursor_type = "row"
        self.zebra_stripes = True


class InlineRepeater(Vertical):
    DEFAULT_CSS = """
    InlineRepeater {
        height: 1fr;
    }
    #rep-body {
        height: 1fr;
    }
    #rep-list-panel {
        width: 30%;
        height: 1fr;
        border-right: solid $surface;
    }
    #rep-list-panel > DataTable {
        height: 1fr;
    }
    #rep-detail-panel {
        width: 70%;
        height: 1fr;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._requests: dict[str, dict] = {}
        self._current_id: Optional[str] = None
        self._row_counter = 0

    def compose(self) -> ComposeResult:
        with Horizontal(id="rep-body"):
            with Vertical(id="rep-list-panel"):
                yield Label("[bold]Requests[/]", id="rep-list-title")
                yield RepeaterTable(id="rep-request-table")
            with Vertical(id="rep-detail-panel"):
                yield RepeaterTab(id="rep-editor-viewer")

    def on_mount(self) -> None:
        tab = self.query_one("#rep-editor-viewer", RepeaterTab)
        tab.on_response = self._on_repeater_response
        tab.display = False

    def add_flow(self, flow: Flow) -> None:
        raw = format_flow_as_raw_request(flow)
        self._row_counter += 1
        row_key = str(self._row_counter)
        self._requests[row_key] = {
            "flow": flow,
            "raw": raw,
            "response_text": None,
        }
        table = self.query_one("#rep-request-table", RepeaterTable)
        ts = datetime.now().strftime("%H:%M:%S")
        table.add_row(
            flow.method,
            flow.url,
            ts,
            str(flow.status_code or ""),
            key=row_key,
        )

    def _on_repeater_response(self, response_text: str) -> None:
        if self._current_id and self._current_id in self._requests:
            self._requests[self._current_id]["response_text"] = response_text

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_key = str(event.row_key.value)
        if row_key not in self._requests:
            return

        self._current_id = row_key
        req = self._requests[row_key]

        tab = self.query_one("#rep-editor-viewer", RepeaterTab)
        tab.display = True

        tab.query_one("#req-editor").text = req["raw"]

        viewer = tab.query_one("#resp-viewer", ResponseViewer)
        if req["response_text"]:
            viewer.text = req["response_text"]
        else:
            viewer.text = ""
