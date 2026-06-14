import asyncio
import logging
from typing import Any, Optional

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

from pwnproxy.shared.hooks import HookBus
from pwnproxy.services.proxy.interceptor.controller import InterceptorController
from apps.terminal.tui.interceptor_widget import InterceptorWidget
from apps.terminal.tui.log_widget import LogTable
from apps.terminal.tui.findings_widget import FindingsTable
from pwnproxy.services.repeater.tui.inline import InlineRepeater
from apps.terminal.tui.scope_widget import ScopeTab
from apps.terminal.tui.scanner_widget import ScannerTab
from apps.terminal.tui.sessions_widget import SessionsTab, SessionsTable
from apps.terminal.tui.ws_client import stream_findings, stream_traffic

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


class SessionPicker(ModalScreen[str]):
    def compose(self) -> ComposeResult:
        yield Container(
            Label("[bold]Select Session[/]"),
            Static("Choose a session to load or create a new one.", id="picker-subtitle"),
            Static("", id="session-list"),
            Input(placeholder="Session number or name...", id="picker-input"),
            Horizontal(
                Button("Load / New", variant="primary", id="picker-load"),
                Button("Start Empty", id="picker-empty"),
            ),
            id="dialog-content",
        )

    def on_mount(self) -> None:
        asyncio.create_task(self._fetch_sessions())
        self.query_one("#picker-input", Input).focus()

    async def _fetch_sessions(self) -> None:
        url = f"http://{self.app._host}:{self.app._api_port}/api/v1/sessions"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, timeout=5)
            if resp.status_code == 200:
                sessions = resp.json()
                if not sessions:
                    self.query_one("#session-list", Static).update("[dim]No sessions found. Type a name and press Load / New to create one.[/]")
                    self._sessions = []
                    return
                lines = []
                for i, s in enumerate(sessions, 1):
                    tag = " [green]*[/]" if s.get("last_active") else ""
                    lines.append(f"  {i}. {s['name']}{tag}")
                self.query_one("#session-list", Static).update("\n".join(lines))
                self._sessions = sessions
        except Exception as e:
            self.query_one("#session-list", Static).update(f"[red]Error: {e}[/]")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "picker-load":
            val = self.query_one("#picker-input", Input).value.strip()
            if not val:
                self.query_one("#picker-input", Input).focus()
                return
            if hasattr(self, "_sessions"):
                try:
                    idx = int(val) - 1
                    if 0 <= idx < len(self._sessions):
                        self.dismiss(self._sessions[idx]["name"])
                        return
                except ValueError:
                    pass
            self.dismiss(val)
        elif event.button.id == "picker-empty":
            self.dismiss("__empty__")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "picker-input":
            val = event.value.strip()
            if not val:
                return
            if hasattr(self, "_sessions"):
                try:
                    idx = int(val) - 1
                    if 0 <= idx < len(self._sessions):
                        self.dismiss(self._sessions[idx]["name"])
                        return
                except ValueError:
                    pass
            self.dismiss(val)


class DashboardApp(App):
    CSS = """
    TabbedContent { height: 1fr; }
    TabPane { height: 1fr; }
    #dialog-content {
        width: 60;
        height: auto;
        padding: 2;
        border: solid $primary;
        background: $surface;
        align: center middle;
    }
    #dialog-content Input {
        width: 40;
    }
    #picker-input {
        margin: 1 0;
    }
    #dialog-content Horizontal {
        height: 3;
        align: center middle;
    }
    #dialog-content Static {
        margin: 1 0;
    }
    #picker-subtitle {
        text-style: dim;
    }
    #session-list {
        height: auto;
        max-height: 12;
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
        scan_manager: Any = None,
    ):
        super().__init__()
        self._host = host
        self._api_port = api_port
        self._hook_bus = hook_bus
        self._interceptor_controller = interceptor_controller
        self._scan_manager = scan_manager
        self._active_session: Optional[str] = None

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
            with TabPane("Scanner", id="tab-scan"):
                yield ScannerTab(id="scanner-tab")
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
        self.push_screen(SessionPicker(), self._on_session_picked)
        if self._interceptor_controller:
            widget = self.query_one("#interceptor-widget", InterceptorWidget)
            self._interceptor_controller.set_on_intercepted(
                lambda flow: widget.post_message(
                    InterceptorWidget.AddFlow(flow)
                )
            )

    def _on_session_picked(self, result: Optional[str]) -> None:
        if result is None or result == "__empty__":
            self.sub_title = "Session: (none)"
            return
        if result == "__new__":
            self.push_screen(SessionNameDialog(), self._on_session_created)
            return
        asyncio.create_task(self._load_session_by_name(result))

    async def _load_session_by_name(self, name: str) -> None:
        url = f"http://{self._host}:{self._api_port}/api/v1/sessions/manage"
        try:
            async with httpx.AsyncClient() as client:
                await client.post(url, json={"action": "load", "name": name}, timeout=5)
            self._active_session = name
            self.sub_title = f"Session: {name}"
            self.notify(f"Loaded session: {name}")
        except Exception as e:
            self.notify(f"Failed to load session: {e}", severity="error")
            self.sub_title = "Session: (none)"

    async def _load_session_info(self) -> None:
        url = f"http://{self._host}:{self._api_port}/api/v1/sessions/active"
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                name = data.get("name")
                self._active_session = name
                self.sub_title = f"Session: {name or '(none)'}"
                if name and data.get("scope_enabled"):
                    self.sub_title += " [scope]"
        except Exception:
            self.sub_title = "Session: (none)"

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

    def on_scanner_tab_findings_detail(self, event: ScannerTab.FindingsDetail) -> None:
        ft = self.query_one("#findings-table", FindingsTable)
        ft.set_url_filter(event.url)
        self.set_timer(0, lambda: setattr(
            self.query_one(TabbedContent), "active", "findings"
        ))
        self.notify(f"Filtering findings by: {event.url[:60]}")

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-intruder":
            from pwnproxy.services.intruder.tui.screen import IntruderScreen
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
        if self._active_session and name == self._active_session and not self._active_session.startswith("default"):
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
                self.notify(f"Saved session '{self._active_session or '(none)'}'")
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
                    self._active_session = None
                    self.sub_title = "Session: (none)"
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
