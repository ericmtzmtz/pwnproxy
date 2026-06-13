import asyncio
from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal
from textual.screen import Screen
from textual.widgets import DataTable, Header, Input, Static

from pwnproxy.services.session.consumer import SessionConsumer
from pwnproxy.services.session.models import SessionToken, TokenCandidate

STATUS_COLORS = {
    "valid": "[green]",
    "expired": "[red]",
    "invalid_signature": "[yellow]",
    "unknown": "[grey]",
}


class TokenScreen(Screen[None]):
    BINDINGS = [
        Binding("escape", "clear_search", "Clear"),
        Binding("c", "copy_token", "Copy"),
    ]

    def __init__(self, consumer: SessionConsumer, name: Optional[str] = None):
        super().__init__(name=name)
        self._consumer = consumer
        self._tokens: list[SessionToken] = []
        self._filter_type: Optional[str] = None

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with Container(id="token-main"):
            yield Static("", id="token-header")
            yield Input(placeholder="Search tokens...", id="token-search")
            yield Static(
                "[bold]Type:[/] [white]All[/] | [green]JWT[/] | [yellow]Cookie[/] | [cyan]CSRF[/]",
                id="token-filters",
            )
            yield DataTable(id="token-table")
            yield Static("", id="token-detail", classes="detail-panel")

    def on_mount(self) -> None:
        table = self.query_one("#token-table", DataTable)
        table.add_columns("TYPE", "LABEL", "STATUS", "VALUE", "COUNT", "LAST SEEN")
        self._refresh()

    def _refresh(self) -> None:
        async def reload():
            tokens = await self._consumer.storage.query(
                token_type=self._filter_type
            )
            self._tokens = tokens
            table = self.query_one("#token-table", DataTable)
            table.clear()
            header_text = f"[bold]Tokens:[/] {len(tokens)} total"
            if tokens:
                jwt_count = sum(1 for t in tokens if t.token_type == "jwt")
                cookie_count = sum(1 for t in tokens if t.token_type == "cookie")
                csrf_count = sum(1 for t in tokens if t.token_type == "csrf")
                header_text += (
                    f"  |  [green]JWT: {jwt_count}[/]  "
                    f"[yellow]Cookie: {cookie_count}[/]  "
                    f"[cyan]CSRF: {csrf_count}[/]"
                )
            self.query_one("#token-header", Static).update(header_text)

            for t in tokens:
                color = STATUS_COLORS.get(t.status, "[grey]")
                type_badge = {
                    "jwt": "[green]JWT[/]",
                    "cookie": "[yellow]COOKIE[/]",
                    "csrf": "[cyan]CSRF[/]",
                }.get(t.token_type, t.token_type.upper())
                table.add_row(
                    type_badge,
                    t.label or "",
                    f"{color}{t.status.upper()}[/]" if t.status else "",
                    (t.token_value or "")[:40],
                    str(t.ref_count),
                    t.last_seen.strftime("%H:%M:%S") if t.last_seen else "",
                )
        asyncio.create_task(reload())

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        idx = event.cursor_key
        if idx is not None and idx < len(self._tokens):
            t = self._tokens[idx]
            parts = [
                f"[bold]Type:[/] {t.token_type}",
                f"[bold]Label:[/] {t.label or 'N/A'}",
                f"[bold]Status:[/] {t.status}",
                f"[bold]Value:[/] {t.token_value}",
                f"[bold]Source:[/] {t.source_url}",
                f"[bold]Ref Count:[/] {t.ref_count}",
                f"[bold]First Seen:[/] {t.first_seen}",
                f"[bold]Last Seen:[/] {t.last_seen}",
            ]
            if t.decoded_header:
                import json as json_mod
                parts.append(
                    f"[bold]JWT Header:[/]\n{json_mod.dumps(t.decoded_header, indent=2)}"
                )
            if t.decoded_payload:
                import json as json_mod
                parts.append(
                    f"[bold]JWT Payload:[/]\n{json_mod.dumps(t.decoded_payload, indent=2)}"
                )
            if t.expires_at:
                parts.append(f"[bold]Expires:[/] {t.expires_at}")
            self.query_one("#token-detail", Static).update("\n\n".join(parts))

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "token-search":
            search = event.value.strip()
            async def do_search():
                tokens = await self._consumer.storage.query(
                    token_type=self._filter_type,
                    search=search if search else None,
                )
                self._tokens = tokens
                table = self.query_one("#token-table", DataTable)
                table.clear()
                for t in tokens:
                    color = STATUS_COLORS.get(t.status, "[grey]")
                    type_badge = {
                        "jwt": "[green]JWT[/]",
                        "cookie": "[yellow]COOKIE[/]",
                        "csrf": "[cyan]CSRF[/]",
                    }.get(t.token_type, t.token_type.upper())
                    table.add_row(
                        type_badge,
                        t.label or "",
                        f"{color}{t.status.upper()}[/]",
                        (t.token_value or "")[:40],
                        str(t.ref_count),
                        t.last_seen.strftime("%H:%M:%S") if t.last_seen else "",
                    )
            asyncio.create_task(do_search())

    def on_static_clicked(self, event: Static.Clicked) -> None:
        if event.static.id == "token-filters":
            pass

    def action_clear_search(self) -> None:
        self.query_one("#token-search", Input).value = ""
        self._refresh()

    def action_copy_token(self) -> None:
        table = self.query_one("#token-table", DataTable)
        idx = table.cursor_row
        if idx is not None and idx < len(self._tokens):
            val = self._tokens[idx].token_value
            import pyperclip
            pyperclip.copy(val)
            self.query_one("#token-detail", Static).update(
                f"[green]Copied to clipboard![/]"
            )

    def on_token(self, token: TokenCandidate) -> None:
        self._refresh()
