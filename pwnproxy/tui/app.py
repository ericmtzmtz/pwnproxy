import asyncio
import logging
from typing import Optional

import httpx

from textual.app import App, ComposeResult
from textual.containers import Container
from textual.widgets import (
    Button,
    Header,
    Static,
    TabbedContent,
    TabPane,
)

from pwnproxy.core.hooks import HookBus
from pwnproxy.tui.log_widget import LogTable
from pwnproxy.tui.findings_widget import FindingsTable
from pwnproxy.tui.sessions_widget import SessionsTable
from pwnproxy.tui.ws_client import stream_findings, stream_traffic

logger = logging.getLogger(__name__)


class DashboardApp(App):
    CSS = """
    TabbedContent { height: 1fr; }
    TabPane { height: 1fr; }
    LogTable { height: 1fr; }
    FindingsTable { height: 1fr; }
    SessionsTable { height: 1fr; }

    .tool-launcher {
        height: 100%;
        align: center middle;
    }
    .tool-launcher > Static {
        text-align: center;
        margin-bottom: 1;
    }
    Button {
        width: 30;
    }
    """

    TITLE = "pwnproxy Dashboard"
    BINDINGS = [("q", "quit", "Quit"), ("ctrl+q", "quit", "Quit")]

    def __init__(
        self,
        host: str = "127.0.0.1",
        api_port: int = 8000,
        hook_bus: Optional[HookBus] = None,
    ):
        super().__init__()
        self._host = host
        self._api_port = api_port
        self._hook_bus = hook_bus

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        with TabbedContent(initial="tab-proxy"):
            with TabPane("Proxy Log", id="tab-proxy"):
                yield Static("", id="debug-log")
                yield LogTable(id="log-table")
            with TabPane("Interceptor", id="interceptor"):
                with Container(classes="tool-launcher"):
                    yield Static("[bold]Interceptor[/]")
                    yield Static(
                        "Inspecting and modifying flows in transit.\n"
                        "Intercepted flows appear here when the proxy\n"
                        "captures matching requests.",
                        id="interceptor-hint",
                    )
            with TabPane("Repeater", id="repeater"):
                with Container(classes="tool-launcher"):
                    yield Static("[bold]Repeater[/]")
                    yield Static("Replay and modify HTTP requests.")
                    yield Button("Launch Repeater", id="btn-repeater", variant="primary")
            with TabPane("Intruder", id="intruder"):
                with Container(classes="tool-launcher"):
                    yield Static("[bold]Intruder[/]")
                    yield Static("Automated fuzzing with payload positions.")
                    yield Button("Launch Intruder", id="btn-intruder", variant="primary")
            with TabPane("Sessions", id="tab-sessions"):
                yield SessionsTable(id="sessions-table")
                yield Button("Launch Sessions", id="btn-sessions", variant="primary")
            with TabPane("Findings", id="findings"):
                yield FindingsTable(id="findings-table")

    def on_mount(self) -> None:
        self.set_timer(2.0, self._start_streams)

    async def _start_streams(self) -> None:
        self.notify("Starting streams...")
        asyncio.create_task(self._consume_traffic())
        asyncio.create_task(self._consume_findings())

    async def _consume_traffic(self) -> None:
        async for msg in stream_traffic(self._host, self._api_port):
            self.notify(f"{msg.get('method')} {msg.get('url','')[:40]}")
            self.query_one("#log-table", LogTable).post_message(LogTable.AddFlow(msg))

    async def _consume_findings(self) -> None:
        async for msg in stream_findings(self._host, self._api_port):
            self.notify(f"Finding: {msg.get('scanner','')} {msg.get('severity','')}")
            self.query_one("#findings-table", FindingsTable).post_message(FindingsTable.AddFinding(msg))

    def on_button_pressed(self, event: Button.Pressed) -> None:
        btn_id = event.button.id
        if btn_id == "btn-repeater":
            from pwnproxy.repeater.tui.screen import RepeaterScreen
            self.push_screen(RepeaterScreen())
        elif btn_id == "btn-intruder":
            from pwnproxy.intruder.tui.screen import IntruderScreen
            self.push_screen(IntruderScreen())
        elif btn_id == "btn-sessions":
            self._open_sessions()

    def on_tabbed_content_tab_activated(
        self, event: TabbedContent.TabActivated
    ) -> None:
        if event.tab.id == "tab-sessions":
            asyncio.create_task(self._load_sessions())

    async def _load_sessions(self) -> None:
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

    def _open_sessions(self) -> None:
        if self._hook_bus:
            from pwnproxy.modules.session_manager.consumer import SessionConsumer
            from pwnproxy.modules.session_manager.tui.screen import TokenScreen
            consumer = SessionConsumer(hook_bus=self._hook_bus)
            self.push_screen(TokenScreen(consumer=consumer))
        else:
            from pwnproxy.repeater.tui.screen import RepeaterScreen
            self.push_screen(RepeaterScreen())
