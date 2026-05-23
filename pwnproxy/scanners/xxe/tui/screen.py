import asyncio
from pathlib import Path
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import Button, DataTable, Header, Static

from pwnproxy.scanners.xxe.models import XxeFinding
from pwnproxy.scanners.xxe.scanner import XXEScanner


class XxeScannerScreen(Screen[None]):
    BINDINGS = [
        Binding("e", "export_json", "Export JSON"),
        Binding("space", "toggle_scanner", "Start/Stop"),
    ]

    def __init__(self, scanner: XXEScanner, name: Optional[str] = None):
        super().__init__(name=name)
        self._scanner = scanner
        self._findings: list[XxeFinding] = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Container(id="xxe-main"):
            with Horizontal(id="xxe-status-bar"):
                yield Static("", id="xxe-status-text")
                yield Static("", id="xxe-counters")
                yield Button("Export JSON", id="btn-export", variant="default")
            yield DataTable(id="xxe-table")
            yield Static("", id="xxe-detail", classes="detail-panel")

    def on_mount(self) -> None:
        table = self.query_one("#xxe-table", DataTable)
        table.add_columns("SEV", "URL", "TYPE", "MUTATION", "CONF")
        self._update_status()
        self._refresh_table()

    def _update_status(self) -> None:
        status = self._scanner.status()
        running_text = "[green]RUNNING[/]" if status["running"] else "[red]STOPPED[/]"
        oob_text = f"OOB: [green]{status['oob_domain']}[/]" if status["oob_domain"] else "OOB: [red]not configured[/]"
        self.query_one("#xxe-status-text", Static).update(
            f"[bold]XXE SCANNER[/] [{running_text}] [{oob_text}]"
        )
        self.query_one("#xxe-counters", Static).update(
            f"Findings: {status['findings']}  "
            f"Flows: {status['flows_processed']}  "
            f"Scanned: {status['params_scanned']}"
        )

    def _refresh_table(self) -> None:
        async def reload():
            findings = await self._scanner._storage.get_findings()
            self._findings = findings
            table = self.query_one("#xxe-table", DataTable)
            table.clear()
            if not findings:
                self.query_one("#xxe-detail", Static).update(
                    f"No XXE findings yet. Scanner is {'running' if self._scanner.is_running else 'stopped'}."
                )
                return
            for f in findings:
                sev_icon = "🔴" if f.severity == "critical" else "🟠"
                table.add_row(
                    sev_icon,
                    f.url[:80],
                    f.technique.upper(),
                    f.mutation,
                    f.confidence.upper(),
                )
        asyncio.create_task(reload())

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_key
        if idx is not None and idx < len(self._findings):
            f = self._findings[idx]
            detail = (
                f"[bold]URL:[/] {f.url}\n"
                f"[bold]Param:[/] {f.param_name} ({f.param_location})\n"
                f"[bold]Technique:[/] {f.technique}\n"
                f"[bold]Mutation:[/] {f.mutation}\n"
                f"[bold]Severity:[/] {f.severity}\n"
                f"[bold]Confidence:[/] {f.confidence}\n"
                f"[bold]OOB Domain:[/] {f.oob_domain or 'N/A'}\n"
                f"[bold]Payload:[/] {f.payload}\n"
                f"[bold]Evidence:[/] {f.evidence or 'N/A'}\n"
                f"[bold]Time:[/] {f.timestamp}"
            )
            self.query_one("#xxe-detail", Static).update(detail)

    def action_toggle_scanner(self) -> None:
        if self._scanner.is_running:
            asyncio.create_task(self._scanner.stop())
        else:
            asyncio.create_task(self._scanner.start())
        self._update_status()

    def action_export_json(self) -> None:
        async def do_export():
            path = await self._scanner._storage.export_json()
            self.query_one("#xxe-detail", Static).update(
                f"[green]Exported to {path}[/]"
            )
        asyncio.create_task(do_export())

    def on_finding(self, finding: XxeFinding) -> None:
        self._findings.insert(0, finding)
        self._update_status()
        self._refresh_table()
