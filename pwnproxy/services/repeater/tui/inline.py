from datetime import datetime
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.widgets import DataTable, Label

from pwnproxy.shared.models import Flow
from pwnproxy.services.repeater.integration import format_flow_as_raw_request
from pwnproxy.services.repeater.tui.tab import RepeaterTab
from pwnproxy.services.repeater.tui.viewer import ResponseViewer


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
        height: 3;
        width: 1fr;
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
        self._current_id = row_key
        self._update_info_bar_from_current()

    def _on_repeater_response(self, data: dict) -> None:
        if self._current_id and self._current_id in self._requests:
            self._requests[self._current_id].update({
                "response_text": data["text"],
                "status_code": data["status_code"],
                "response_size": data["size"],
                "duration_ms": data["duration_ms"],
                "sent_method": data["method"],
                "sent_path": data["path"],
            })
            self._update_info_bar_from_current()

    def _update_info_bar_from_current(self) -> None:
        if not self._current_id or self._current_id not in self._requests:
            return
        req_data = self._requests[self._current_id]
        flow = req_data["flow"]
        method = req_data.get("sent_method") or flow.method
        path = req_data.get("sent_path") or flow.url
        size = len(req_data["raw"])
        status = req_data.get("status_code") or flow.status_code or ""
        resp_size = req_data.get("response_size")
        dur = req_data.get("duration_ms")
        ts = ""
        parts = [method, path]
        if status:
            parts.append(f"[{status}]")
        parts.append(f"Req: {size}B")
        if resp_size is not None:
            parts.append(f"Res: {resp_size}B")
        if dur:
            parts.append(f"{dur:.0f}ms")
        bar = self.query_one("#rep-info-bar", Label)
        bar.update("  ".join(parts))

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

        self._update_info_bar_from_current()


