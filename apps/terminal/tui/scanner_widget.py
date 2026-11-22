import asyncio
import logging

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, DataTable, Label, Static

logger = logging.getLogger(__name__)

MAX_HISTORY_ROWS = 5000


def scanner_options() -> list[tuple[str, str]]:
    """Return ``(name, button label)`` for every scanner in the plugin catalog.

    The names come from ``pwnproxy.plugins.core.catalog`` (built-ins plus
    installed packages by entry point), never from a literal list: a hardcoded
    one here was one of the four registries that hid external scanners. The
    label is derived from the name (upper-cased and clipped to the button
    width) so the widget needs no second table either.
    """
    from pwnproxy.plugins.core.catalog import discover_plugins

    options: list[tuple[str, str]] = []
    for record in discover_plugins():
        metadata = record.metadata
        if metadata is not None and metadata.category and metadata.category != "scanner":
            continue
        options.append((record.name, record.name.replace("-", " ").upper()[:10]))
    return options


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
    #btn-view-findings {
        width: auto;
        margin: 1 0 0 2;
    }
    """

    class FindingsDetail(Message):
        def __init__(self, url: str) -> None:
            self.url = url
            super().__init__()

    def compose(self) -> ComposeResult:
        self._options = scanner_options()
        with Horizontal(id="scan-controls"):
            yield Label("Scanners:", id="scan-controls-label")
            for name, label in self._options:
                yield Button(
                    label,
                    id=f"btn-scan-{name}",
                    classes="scanner-btn off",
                )
            yield Button("Pause All", id="btn-scan-pause-all", variant="warning")
            yield Button("Resume All", id="btn-scan-resume-all", variant="default")
        yield DataTable(id="scan-history")
        with Vertical(id="scan-detail"):
            yield Label("Findings Detail", id="scan-detail-label")
            yield Static("Select a row to view findings", id="scan-detail-empty")
            yield Button("View in Findings Tab", id="btn-view-findings", variant="primary")

    def on_mount(self) -> None:
        table = self.query_one("#scan-history", DataTable)
        table.add_columns("URL", "Method", "Scanners", "Findings", "Avg Time (ms)")
        table.cursor_type = "row"
        table.zebra_stripes = True
        self.query_one("#btn-view-findings", Button).visible = False
        self.set_interval(2.0, self._refresh)

    async def _refresh(self) -> None:
        mgr = getattr(self.app, "_scan_manager", None)
        if not mgr:
            return
        self._update_button_states(mgr)
        await self._refresh_history(mgr)

    def _update_button_states(self, mgr) -> None:
        statuses = mgr.status()
        for name, base_label in self._options:
            btn = self.query_one(f"#btn-scan-{name}", Button)
            s = statuses.get(name, {})
            running = s.get("running", False)
            paused = s.get("paused", False)
            btn.remove_class("on", "off", "paused")
            if running and paused:
                btn.add_class("paused")
                btn.label = f"⏸ {base_label}"
            elif running:
                btn.add_class("on")
                btn.label = f"▶ {base_label}"
            else:
                btn.add_class("off")
                btn.label = f"■ {base_label}"

    async def _refresh_history(self, mgr) -> None:
        rows = await mgr._scan_log_store.query_logs_grouped_by_url(limit=MAX_HISTORY_ROWS)
        table = self.query_one("#scan-history", DataTable)
        table.clear()
        for r in rows:
            table.add_row(
                r["url"],
                r["method"],
                r["scanners"],
                str(r["total_findings"]),
                str(r["avg_duration_ms"]),
                key=r["url"],
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
        seen: set[str] = set()
        for e in entries:
            sn = e['scanner_name']
            if sn in seen:
                continue
            seen.add(sn)
            label = (
                f"[bold]{sn}[/] "
                f"({e['status']}) — "
                f"findings: {e['finding_count']}, "
                f"time: {e['duration_ms']}ms"
            )
            detail.mount(Static(label))
        btn = self.query_one("#btn-view-findings", Button)
        if entries:
            btn.visible = True
            self._detail_url = url
        else:
            btn.visible = False
            empty.visible = True

    def on_button_pressed(self, event: Button.Pressed) -> None:
        bid = event.button.id or ""
        if bid == "btn-view-findings":
            url = getattr(self, "_detail_url", "")
            if url:
                self.post_message(self.FindingsDetail(url))
            return
        mgr = getattr(self.app, "_scan_manager", None)
        if not mgr:
            self.app.notify("Scanner controls not available in new architecture", severity="warning")
            return
        if bid.startswith("btn-scan-") and not bid.endswith("-all"):
            name = bid.replace("btn-scan-", "")
            if name in {option[0] for option in self._options}:
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
        url = event.row_key.value
        if url:
            asyncio.create_task(self._show_findings_detail(url))
