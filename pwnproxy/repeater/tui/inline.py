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
    #rep-detail-panel {
        height: 2fr;
    }
    #rep-info-bar {
        height: 1;
        background: $surface;
        border-top: solid $primary;
        border-bottom: solid $primary;
        content-align: center middle;
    }
    #rep-list-panel {
        height: 1fr;
        border-top: solid $surface;
    }
    #rep-request-table {
        height: 1fr;
    }
    """

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._requests: dict[str, dict] = {}
        self._current_id: Optional[str] = None
        self._row_counter = 0

    def compose(self) -> ComposeResult:
        with Vertical(id="rep-detail-panel"):
            yield RepeaterTab(id="rep-editor-viewer")
        yield Label("", id="rep-info-bar")
        with Vertical(id="rep-list-panel"):
            yield Label("[bold]Requests[/]", id="rep-list-title")
            yield RepeaterTable(id="rep-request-table")

    def on_mount(self) -> None:
        tab = self.query_one("#rep-editor-viewer", RepeaterTab)
        tab.on_response = self._on_repeater_response

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
        self._update_info_bar(flow, ts, len(raw))

    def _on_repeater_response(self, response_text: str) -> None:
        if self._current_id and self._current_id in self._requests:
            self._requests[self._current_id]["response_text"] = response_text

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row_key = str(event.row_key.value)
        if row_key not in self._requests:
            return

        self._current_id = row_key
        req = self._requests[row_key]
        flow = req["flow"]

        tab = self.query_one("#rep-editor-viewer", RepeaterTab)
        tab.display = True

        tab.query_one("#req-editor").text = req["raw"]

        viewer = tab.query_one("#resp-viewer", ResponseViewer)
        if req["response_text"]:
            viewer.text = req["response_text"]
        else:
            viewer.text = ""

        self._update_info_bar(flow, "", len(req["raw"]))

    def _update_info_bar(self, flow: Flow, ts: str, size: int) -> None:
        bar = self.query_one("#rep-info-bar", Label)
        bar_text = f"  {flow.method}  {flow.url}  [{flow.status_code or ''}]  {size}B  {ts}"
        if self._current_id and self._current_id in self._requests:
            resp = self._requests[self._current_id].get("response_text")
            if resp:
                bar_text += f"  |  Response: {len(resp)}B"
        bar.update(bar_text.strip())
