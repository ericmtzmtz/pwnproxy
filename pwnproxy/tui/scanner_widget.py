import asyncio
import logging
from typing import Optional

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, DataTable, Label, Static

logger = logging.getLogger(__name__)

SCANNER_NAMES = ["sqli", "xss", "lfi", "xxe", "ssrf"]
SCANNER_DISPLAY = {"sqli": "SQLi", "xss": "XSS", "lfi": "LFI", "xxe": "XXE", "ssrf": "SSRF"}
MAX_HISTORY_ROWS = 5000


class ScannerTab(Vertical):
    DEFAULT_CSS = """
    ScannerTab { height: 1fr; }
    #scan-controls {
        height: auto;
        padding: 0 1;
        align: center middle;
    }
    .scanner-btn {
        width: 12;
        height: 3;
        margin: 0 1;
    }
    .scanner-btn.on {
        background: green;
        color: white;
    }
    .scanner-btn.off {
        background: darkgray;
        color: black;
    }
    .scanner-btn.paused {
        background: orange;
        color: black;
    }
    #scan-controls-label {
        width: auto;
        margin: 0 1 0 0;
        text-style: bold;
    }
    #scan-history {
        height: 2fr;
        margin: 1 0 0 0;
    }
    #scan-detail {
        height: 1fr;
        margin: 1 0 0 0;
    }
    #scan-detail-label {
        text-style: bold;
        padding: 0 1;
    }
    #scan-detail-empty {
        color: gray;
        padding: 0 2;
    }
    """

    class FindingsDetail(Message):
        def __init__(self, url: str) -> None:
            self.url = url
            super().__init__()

    def compose(self) -> ComposeResult:
        with Horizontal(id="scan-controls"):
            yield Label("Scanners:", id="scan-controls-label")
            for name in SCANNER_NAMES:
                yield Button(
                    SCANNER_DISPLAY[name],
                    id=f"btn-scan-{name}",
                    classes="scanner-btn off",
                )
            yield Button("Pause All", id="btn-scan-pause-all", variant="warning")
            yield Button("Resume All", id="btn-scan-resume-all", variant="default")
        yield DataTable(id="scan-history")
        with Vertical(id="scan-detail"):
            yield Label("Findings Detail", id="scan-detail-label")
            yield Static("Select a row to view findings", id="scan-detail-empty")

    def on_mount(self) -> None:
        table = self.query_one("#scan-history", DataTable)
        table.add_columns("URL", "Method", "Scanners", "Findings", "Avg Time (ms)")
        table.cursor_type = "row"
        table.zebra_stripes = True
        self.set_interval(2.0, self._refresh)

    async def _refresh(self) -> None:
        mgr = getattr(self.app, "_scan_manager", None)
        if not mgr:
            return
        self._update_button_states(mgr)
        await self._refresh_history(mgr)

    def _update_button_states(self, mgr) -> None:
        statuses = mgr.status()
        for name in SCANNER_NAMES:
            btn = self.query_one(f"#btn-scan-{name}", Button)
            s = statuses.get(name, {})
            running = s.get("running", False)
            paused = s.get("paused", False)
            btn.remove_class("on", "off", "paused")
            if running and paused:
                btn.add_class("paused")
                btn.label = f"⏸ {SCANNER_DISPLAY[name]}"
            elif running:
                btn.add_class("on")
                btn.label = f"▶ {SCANNER_DISPLAY[name]}"
            else:
                btn.add_class("off")
                btn.label = f"■ {SCANNER_DISPLAY[name]}"

    async def _refresh_history(self, mgr) -> None:
        rows = await mgr._scan_log_store.query_logs_grouped_by_url(limit=MAX_HISTORY_ROWS)
        table = self.query_one("#scan-history", DataTable)
        table.clear()
        for r in rows:
            table.add_row(
                r["url"][:100],
                r["method"],
                r["scanners"],
                str(r["total_findings"]),
                str(r["avg_duration_ms"]),
                height=1,
            )

    async def _show_findings_detail(self, url: str) -> None:
        mgr = getattr(self.app, "_scan_manager", None)
        if not mgr:
            return
        detail = self.query_one("#scan-detail", Vertical)
        existing = detail.query("Static")
        for w in list(existing):
            if w.id != "scan-detail-label" and w.id != "scan-detail-empty":
                w.remove()
        empty = self.query_one("#scan-detail-empty", Static)
        empty.visible = False
        entries = await mgr._scan_log_store.query_findings_for_url(url)
        for e in entries:
            label = (
                f"[bold]{e['scanner_name']}[/] "
                f"({e['status']}) — "
                f"findings: {e['finding_count']}, "
                f"time: {e['duration_ms']}ms"
            )
            detail.mount(Static(label))
        if not entries:
            empty.visible = True

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        mgr = getattr(self.app, "_scan_manager", None)
        if not mgr:
            return
        if bid.startswith("btn-scan-") and not bid.endswith("-all"):
            name = bid.replace("btn-scan-", "")
            if name in SCANNER_NAMES:
                s = mgr.status().get(name, {})
                if s.get("running", False):
                    asyncio.create_task(mgr.stop(name))
                else:
                    asyncio.create_task(mgr.start(name))
        elif bid == "btn-scan-pause-all":
            mgr.pause_all()
        elif bid == "btn-scan-resume-all":
            mgr.resume_all()

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row = event.row_key.value
        if row is not None:
            url = str(event.data_table.get_row_at(event.cursor_key)[0])
            asyncio.create_task(self._show_findings_detail(url))
