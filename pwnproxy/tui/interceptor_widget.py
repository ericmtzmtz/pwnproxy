import logging
from datetime import datetime
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, DataTable, Static

from pwnproxy.core.models import Flow
from pwnproxy.modules.interceptor.controller import InterceptorController

logger = logging.getLogger(__name__)


class InterceptorWidget(Vertical):
    DEFAULT_CSS = """
    #interceptor-widget {
        height: 1fr;
        layout: vertical;
    }
    #interceptor-header {
        height: auto;
        align: center middle;
        padding: 1;
    }
    #interceptor-table {
        height: 1fr;
    }
    #interceptor-actions {
        height: auto;
        align: center middle;
        padding: 0;
    }
    .interceptor-act-col {
        height: auto;
        align: center middle;
    }
    .interceptor-act-col Button {
        width: 20;
        height: 3;
        margin: 0 1;
    }
    """
    class AddFlow(Message):
        def __init__(self, flow: Flow) -> None:
            self.flow = flow
            super().__init__()

    class SendToRepeater(Message):
        def __init__(self, flow: Flow) -> None:
            self.flow = flow
            super().__init__()

    def __init__(self, controller: InterceptorController, **kwargs):
        super().__init__(**kwargs)
        self._controller = controller

    def compose(self) -> ComposeResult:
        with Horizontal(id="interceptor-header"):
            yield Static("[bold]Interceptor[/]", id="interceptor-title")
            yield Button("ON", id="btn-interceptor-toggle", variant="success")
        yield DataTable(id="interceptor-table")
        with Horizontal(id="interceptor-actions"):
            with Vertical(classes="interceptor-act-col"):
                yield Button("Forward", id="btn-iw-forward")
                yield Button("Drop", id="btn-iw-drop", variant="error")
            with Vertical(classes="interceptor-act-col"):
                yield Button("Forward All", id="btn-iw-forward-all")
                yield Button("Drop All", id="btn-iw-drop-all", variant="error")
            with Vertical(classes="interceptor-act-col"):
                yield Button("Send to Repeater", id="btn-iw-repeater")
                yield Button("Send to Intruder", id="btn-iw-intruder")
            with Vertical(classes="interceptor-act-col"):
                yield Button("Scan", id="btn-iw-scan", variant="primary")

    def on_mount(self) -> None:
        table = self.query_one("#interceptor-table", DataTable)
        table.add_columns("Method", "URL", "Status", "Time")
        table.cursor_type = "row"
        table.zebra_stripes = True

    def on_interceptor_widget_add_flow(self, event: AddFlow) -> None:
        flow = event.flow
        table = self.query_one("#interceptor-table", DataTable)
        ts = datetime.now().strftime("%H:%M:%S")
        table.add_row(
            flow.method,
            flow.url,
            str(flow.status_code or ""),
            ts,
            key=flow.id,
        )

    def _get_selected_flow_id(self) -> Optional[str]:
        table = self.query_one("#interceptor-table", DataTable)
        try:
            row = table.coordinate_to_cell_key(table.cursor_coordinate)
        except Exception:
            return None
        if row is None:
            return None
        return str(row.row_key.value)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        flow_id = str(event.row_key.value)
        flow = self._controller.pending.get(flow_id)
        if not flow:
            return
        snapshot = self._controller.get_snapshot(flow_id)
        if not snapshot:
            return
        from pwnproxy.modules.interceptor.tui.screen import InterceptorScreen
        self.app.push_screen(InterceptorScreen(self._controller, flow, snapshot))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id
        if bid == "btn-interceptor-toggle":
            self._controller.toggle()
            btn = self.query_one("#btn-interceptor-toggle", Button)
            if self._controller.enabled:
                btn.label = "ON"
                btn.variant = "success"
            else:
                btn.label = "OFF"
                btn.variant = "error"
            return

        flow_id = self._get_selected_flow_id()
        if not flow_id and bid not in ("btn-iw-forward-all", "btn-iw-drop-all", "btn-interceptor-toggle"):
            return

        if bid == "btn-iw-forward":
            self._controller.forward(flow_id)
            self._remove_row(flow_id)
        elif bid == "btn-iw-drop":
            self._controller.drop(flow_id)
            self._remove_row(flow_id)
        elif bid == "btn-iw-forward-all":
            self._controller.forward_all()
            self._clear_table()
        elif bid == "btn-iw-drop-all":
            self._controller.drop_all()
            self._clear_table()
        elif bid == "btn-iw-repeater":
            self._open_repeater(flow_id)
        elif bid == "btn-iw-intruder":
            self._open_intruder(flow_id)
        elif bid == "btn-iw-scan":
            self._trigger_scan(flow_id)

    def _clear_table(self) -> None:
        table = self.query_one("#interceptor-table", DataTable)
        try:
            table.clear()
            table.add_columns("Method", "URL", "Status", "Time")
        except Exception:
            pass

    def _remove_row(self, flow_id: Optional[str]) -> None:
        if not flow_id:
            return
        table = self.query_one("#interceptor-table", DataTable)
        try:
            table.remove_row(flow_id)
        except Exception:
            pass

    def _open_repeater(self, flow_id: str) -> None:
        flow = self._controller.pending.get(flow_id)
        if not flow:
            return
        self.app.post_message(self.SendToRepeater(flow))

    def _open_intruder(self, flow_id: str) -> None:
        flow = self._controller.pending.get(flow_id)
        if not flow:
            return
        from pwnproxy.repeater.integration import format_flow_as_raw_request
        from pwnproxy.intruder.tui.screen import IntruderScreen
        raw = format_flow_as_raw_request(flow)
        screen = IntruderScreen(initial_request=raw)
        self.app.push_screen(screen)

    def _trigger_scan(self, flow_id: str) -> None:
        flow = self._controller.pending.get(flow_id)
        if not flow:
            return
        from pwnproxy.core.hooks import HookEvent
        self.app._hook_bus.publish(HookEvent(type="request", flow=flow))
