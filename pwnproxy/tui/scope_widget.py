import asyncio
import logging
from typing import Optional

import httpx

from textual.app import ComposeResult
from textual.containers import Horizontal, Vertical
from textual.message import Message
from textual.widgets import Button, DataTable, Input, Label, Static

logger = logging.getLogger(__name__)


class ScopeTable(DataTable):
    class RemovePattern(Message):
        def __init__(self, pattern: str, table_type: str) -> None:
            self.pattern = pattern
            self.table_type = table_type
            super().__init__()

    def __init__(self, table_type: str, **kwargs):
        super().__init__(**kwargs)
        self._table_type = table_type  # "in_scope" or "out_of_scope"

    def on_mount(self) -> None:
        self.add_columns("Pattern", "Remove")
        self.cursor_type = "row"
        self.zebra_stripes = True

    def populate(self, patterns: list[str]) -> None:
        self.clear()
        self.add_columns("Pattern", "Remove")
        for p in patterns:
            label = p[:80] + ("..." if len(p) > 80 else "")
            self.add_row(label, "[red]X[/]", height=1)

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        row = event.row_key.value
        if row is not None:
            try:
                pattern = self.get_row_at(event.cursor_key)[0]
                self.post_message(self.RemovePattern(str(pattern), self._table_type))
            except Exception:
                pass


class ScopeTab(Vertical):
    def __init__(self, host: str = "127.0.0.1", api_port: int = 8000, **kwargs):
        super().__init__(**kwargs)
        self._host = host
        self._api_port = api_port
        self._scope: dict = {}

    def compose(self) -> ComposeResult:
        yield Static("", id="scope-title")
        with Horizontal(id="scope-toggle-row"):
            yield Button("Enable Scope", id="btn-scope-toggle", variant="primary")
        with Horizontal(id="scope-tables"):
            with Vertical(classes="scope-panel", id="scope-in-panel"):
                yield Label("[bold]In-Scope[/]", classes="scope-panel-title")
                yield ScopeTable("in_scope", id="scope-in-table")
                yield Input(placeholder="Add pattern (e.g. *.target.com)", id="scope-in-input")
                yield Button("Add", id="btn-scope-in-add")
            with Vertical(classes="scope-panel", id="scope-out-panel"):
                yield Label("[bold]Out-of-Scope[/]", classes="scope-panel-title")
                yield ScopeTable("out_of_scope", id="scope-out-table")
                yield Input(placeholder="Add pattern (e.g. https://ads.com/*)", id="scope-out-input")
                yield Button("Add", id="btn-scope-out-add")

    def on_mount(self) -> None:
        asyncio.create_task(self._load_scope())

    async def _load_scope(self) -> None:
        url = f"http://{self._host}:{self._api_port}/api/v1/sessions/scope"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, timeout=5)
            if resp.status_code == 200:
                self._scope = resp.json()
                self._refresh_ui()
            else:
                self.notify("Failed to load scope", severity="error")
        except Exception as e:
            self.notify(f"Scope load error: {e}", severity="error")

    def _refresh_ui(self) -> None:
        in_table = self.query_one("#scope-in-table", ScopeTable)
        out_table = self.query_one("#scope-out-table", ScopeTable)
        in_table.populate(self._scope.get("in_scope", []))
        out_table.populate(self._scope.get("out_of_scope", []))
        toggle = self.query_one("#btn-scope-toggle", Button)
        enabled = self._scope.get("enabled", False)
        toggle.label = "Disable Scope" if enabled else "Enable Scope"
        toggle.variant = "primary" if enabled else "default"
        title = self.query_one("#scope-title", Static)
        status = "[green]ENABLED[/]" if enabled else "[yellow]DISABLED[/]"
        title.update(f"[bold]Web Scope Configuration[/] — Scope is {status}")

    async def _save_scope(self) -> None:
        url = f"http://{self._host}:{self._api_port}/api/v1/sessions/scope"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.put(url, json=self._scope, timeout=5)
            if resp.status_code == 200:
                self.notify("Scope updated")
                self._refresh_ui()
            else:
                self.notify(f"Failed to save scope: {resp.text}", severity="error")
        except Exception as e:
            self.notify(f"Scope save error: {e}", severity="error")

    def _on_scope_table_remove_pattern(self, event: ScopeTable.RemovePattern) -> None:
        pattern = event.pattern
        table_type = event.table_type
        patterns = self._scope.get(table_type, [])
        if pattern in patterns:
            patterns.remove(pattern)
            self._scope[table_type] = patterns
            asyncio.create_task(self._save_scope())

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-scope-toggle":
            self._scope["enabled"] = not self._scope.get("enabled", False)
            asyncio.create_task(self._save_scope())
        elif event.button.id == "btn-scope-in-add":
            self._add_pattern("in_scope", "#scope-in-input")
        elif event.button.id == "btn-scope-out-add":
            self._add_pattern("out_of_scope", "#scope-out-input")

    def _add_pattern(self, table_type: str, input_id: str) -> None:
        inp = self.query_one(input_id, Input)
        pattern = inp.value.strip()
        if not pattern:
            self.notify("Enter a pattern first", severity="warning")
            return
        patterns = self._scope.get(table_type, [])
        if pattern in patterns:
            self.notify(f"Pattern already exists in {table_type}", severity="warning")
            return
        patterns.append(pattern)
        self._scope[table_type] = patterns
        inp.value = ""
        asyncio.create_task(self._save_scope())
