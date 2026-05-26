import asyncio
import logging
from typing import Optional

import httpx

from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Header,
    Footer,
    Input,
    Label,
    Static,
    TabbedContent,
    TabPane,
)

from pwnproxy.core.hooks import HookBus
from pwnproxy.modules.interceptor.controller import InterceptorController
from pwnproxy.tui.interceptor_widget import InterceptorWidget
from pwnproxy.tui.log_widget import LogTable
from pwnproxy.tui.findings_widget import FindingsTable
from pwnproxy.repeater.tui.inline import InlineRepeater
from pwnproxy.tui.scope_widget import ScopeTab
from pwnproxy.tui.sessions_widget import SessionsTab, SessionsTable
from pwnproxy.tui.ws_client import stream_findings, stream_traffic

logger = logging.getLogger(__name__)


class SessionNameDialog(ModalScreen[str]):
    def compose(self) -> ComposeResult:
        yield Container(
            Label("[bold]New Session[/]"),
            Input(placeholder="Session name...", id="session-name-input"),
            Horizontal(
                Button("Create", variant="primary", id="btn-create-confirm"),
                Button("Cancel", id="btn-create-cancel"),
            ),
            id="dialog-content",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-create-confirm":
            name = self.query_one("#session-name-input", Input).value.strip()
            if name:
                self.dismiss(name)
            else:
                self.query_one("#session-name-input", Input).focus()
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "session-name-input":
            name = event.value.strip()
            if name:
                self.dismiss(name)


class ConfirmDialog(ModalScreen[bool]):
    def __init__(self, message: str, title: str = "Confirm"):
        super().__init__()
        self._message = message
        self._title = title

    def compose(self) -> ComposeResult:
        yield Container(
            Label(f"[bold]{self._title}[/]"),
            Label(self._message),
            Horizontal(
                Button("Confirm", variant="primary", id="btn-confirm-yes"),
                Button("Cancel", id="btn-confirm-no"),
            ),
            id="dialog-content",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "btn-confirm-yes":
            self.dismiss(True)
        else:
            self.dismiss(False)


class DashboardApp(App):
    CSS = """
    TabbedContent { height: 1fr; }
    TabPane { height: 1fr; }
    #dialog-content {
        width: 50;
        height: auto;
        padding: 2;
        border: solid $primary;
        background: $surface;
        align: center middle;
    }
    #dialog-content Input {
        width: 40;
    }
    #dialog-content Horizontal {
        height: 3;
        align: center middle;
    }
    .tool-launcher {
        height: 100%;
        align: center middle;
    }
    .tool-launcher > Static {
        text-align: center;
        margin-bottom: 1;
    }
    Button {
        width: 20;
    }
    #dialog-content Button {
        width: 14;
    }
    """

    TITLE = "pwnproxy Dashboard"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("ctrl+q", "quit", "Quit"),
    ]

    def __init__(
        self,
        host: str = "127.0.0.1",
        api_port: int = 8000,
        hook_bus: Optional[HookBus] = None,
        interceptor_controller: Optional[InterceptorController] = None,
    ):
        super().__init__()
        self._host = host
        self._api_port = api_port
        self._hook_bus = hook_bus
        self._interceptor_controller = interceptor_controller
        self._active_session: str = "default"

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with TabbedContent(initial="tab-proxy"):
            with TabPane("Proxy Log", id="tab-proxy"):
                yield Static("", id="debug-log")
                yield LogTable(id="log-table")
            with TabPane("Interceptor", id="interceptor"):
                yield InterceptorWidget(
                    controller=self._interceptor_controller,
                    id="interceptor-widget",
                )
            with TabPane("Repeater", id="repeater"):
                yield InlineRepeater(id="repeater-inline")
            with TabPane("Intruder", id="intruder"):
                with Container(classes="tool-launcher"):
                    yield Static("[bold]Intruder[/]")
                    yield Static("Automated fuzzing with payload positions.")
                    yield Button("Launch Intruder", id="btn-intruder", variant="primary")
            with TabPane("Sessions", id="tab-sessions"):
                yield SessionsTab()
            with TabPane("Scope", id="tab-scope"):
                yield ScopeTab(host=self._host, api_port=self._api_port, id="scope-tab")
            with TabPane("Findings", id="findings"):
                yield FindingsTable(id="findings-table")
        yield Footer()

    def on_mount(self) -> None:
        self.set_timer(2.0, self._start_streams)
        asyncio.create_task(self._load_session_info())
        if self._interceptor_controller:
            widget = self.query_one("#interceptor-widget", InterceptorWidget)
            self._interceptor_controller.set_on_intercepted(
                lambda flow: widget.post_message(
                    InterceptorWidget.AddFlow(flow)
                )
            )

    async def _load_session_info(self) -> None:
        url = f"http://{self._host}:{self._api_port}/api/v1/sessions/active"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                self._active_session = data.get("name", "default")
                if scope_enabled := data.get("scope_enabled"):
                    self._active_session += " [scope]"
                self.sub_title = f"Session: {self._active_session}"
        except Exception:
            self.sub_title = "Session: default"

    async def _start_streams(self) -> None:
        asyncio.create_task(self._consume_traffic())
        asyncio.create_task(self._consume_findings())

    async def _consume_traffic(self) -> None:
        async for msg in stream_traffic(self._host, self._api_port):
            self.query_one("#log-table", LogTable).post_message(LogTable.AddFlow(msg))

    async def _consume_findings(self) -> None:
        async for msg in stream_findings(self._host, self._api_port):
            self.query_one("#findings-table", FindingsTable).post_message(FindingsTable.AddFinding(msg))

    def on_interceptor_widget_send_to_repeater(
        self, event: InterceptorWidget.SendToRepeater
    ) -> None:
        inline = self.query_one("#repeater-inline", InlineRepeater)
        inline.add_flow(event.flow)
        self.notify(f"Sent to Repeater: {event.flow.url[:60]}")
        self.set_timer(0, lambda: setattr(
            self.query_one(TabbedContent), "active", "repeater"
        ))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-intruder":
            from pwnproxy.intruder.tui.screen import IntruderScreen
            self.push_screen(IntruderScreen(api_host=self._host, api_port=self._api_port))
        elif btn_id == "btn-session-new":
            self.push_screen(SessionNameDialog(), self._on_session_created)
        elif btn_id == "btn-session-load":
            self._load_selected_session()
        elif btn_id == "btn-session-save":
            asyncio.create_task(self._save_current_session())
        elif btn_id == "btn-session-rename":
            self._rename_selected_session()
        elif btn_id == "btn-session-delete":
            self._delete_selected_session()

    def _load_selected_session(self) -> None:
        table = self.query_one("#sessions-table", SessionsTable)
        name = table.get_selected_name()
        if not name:
            self.notify("Select a session first", severity="warning")
            return
        if name == self._active_session and not self._active_session.startswith("default"):
            self.notify(f"Session '{name}' is already active")
            return
        self.push_screen(
            ConfirmDialog(f"Load session '{name}'? Current state will be saved first."),
            lambda confirmed: asyncio.create_task(self._do_load(name)) if confirmed else None,
        )

    async def _do_load(self, name: str) -> None:
        url = f"http://{self._host}:{self._api_port}/api/v1/sessions/manage"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json={"action": "load", "name": name}, timeout=10)
            if resp.status_code == 200:
                self._active_session = name
                self.sub_title = f"Session: {name}"
                self.notify(f"Loaded session '{name}'")
                await self._refresh_sessions()
            else:
                self.notify(f"[red]Failed to load session: {resp.text}[/]", severity="error")
        except Exception as e:
            self.notify(f"[red]Error loading session: {e}[/]", severity="error")

    async def _save_current_session(self) -> None:
        url = f"http://{self._host}:{self._api_port}/api/v1/sessions/manage"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json={"action": "save"}, timeout=10)
            if resp.status_code == 200:
                self.notify(f"Saved session '{self._active_session}'")
            else:
                self.notify(f"[red]Failed to save: {resp.text}[/]", severity="error")
        except Exception as e:
            self.notify(f"[red]Error saving: {e}[/]", severity="error")

    def _delete_selected_session(self) -> None:
        table = self.query_one("#sessions-table", SessionsTable)
        name = table.get_selected_name()
        if not name:
            self.notify("Select a session first", severity="warning")
            return
        if name == "default":
            self.notify("Cannot delete the default session", severity="error")
            return
        self.push_screen(
            ConfirmDialog(f"Delete session '{name}'? This cannot be undone."),
            lambda confirmed: asyncio.create_task(self._do_delete(name)) if confirmed else None,
        )

    async def _do_delete(self, name: str) -> None:
        url = f"http://{self._host}:{self._api_port}/api/v1/sessions/manage"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json={"action": "delete", "name": name}, timeout=10)
            if resp.status_code == 200:
                self.notify(f"Deleted session '{name}'")
                if name == self._active_session:
                    self._active_session = "default"
                    self.sub_title = "Session: default"
                await self._refresh_sessions()
            else:
                self.notify(f"[red]Failed to delete: {resp.text}[/]", severity="error")
        except Exception as e:
            self.notify(f"[red]Error deleting: {e}[/]", severity="error")

    def _rename_selected_session(self) -> None:
        table = self.query_one("#sessions-table", SessionsTable)
        name = table.get_selected_name()
        if not name:
            self.notify("Select a session first", severity="warning")
            return
        if name == "default":
            self.notify("Cannot rename the default session", severity="error")
            return
        self.push_screen(
            SessionNameDialog(),
            lambda new_name: asyncio.create_task(self._do_rename(name, new_name)) if new_name else None,
        )

    async def _do_rename(self, old_name: str, new_name: str) -> None:
        if old_name == new_name:
            self.notify("New name is the same as current")
            return
        url = f"http://{self._host}:{self._api_port}/api/v1/sessions/manage"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json={"action": "rename", "name": old_name, "new_name": new_name}, timeout=10)
            if resp.status_code == 200:
                self._active_session = new_name if self._active_session == old_name else self._active_session
                self.sub_title = f"Session: {self._active_session}"
                self.notify(f"Renamed session '{old_name}' -> '{new_name}'")
                await self._refresh_sessions()
            else:
                detail = resp.json().get("detail", resp.text)
                self.notify(f"[red]Failed: {detail}[/]", severity="error")
        except Exception as e:
            self.notify(f"[red]Error: {e}[/]", severity="error")

    def _on_session_created(self, name: Optional[str]) -> None:
        if name:
            asyncio.create_task(self._do_create(name))

    async def _do_create(self, name: str) -> None:
        url = f"http://{self._host}:{self._api_port}/api/v1/sessions/manage"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(url, json={"action": "create", "name": name}, timeout=10)
            if resp.status_code == 200:
                self._active_session = name
                self.sub_title = f"Session: {name}"
                self.notify(f"Created session '{name}'")
                await self._refresh_sessions()
            else:
                detail = resp.json().get("detail", resp.text)
                self.notify(f"[red]Failed: {detail}[/]", severity="error")
        except Exception as e:
            self.notify(f"[red]Error: {e}[/]", severity="error")

    def on_tabbed_content_tab_activated(
        self, event: TabbedContent.TabActivated
    ) -> None:
        if event.pane.id == "tab-sessions":
            asyncio.create_task(self._refresh_sessions())

    async def _refresh_sessions(self) -> None:
        url = f"http://{self._host}:{self._api_port}/api/v1/sessions"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, timeout=10)
            resp.raise_for_status()
            data = resp.json()
            self.query_one("#sessions-table", SessionsTable).post_message(
                SessionsTable.LoadSessions(data)
            )
        except Exception as e:
            self.notify(f"[red]Sessions load error: {e}[/]", severity="error")
