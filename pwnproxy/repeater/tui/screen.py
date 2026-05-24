from typing import Optional

from textual.app import ComposeResult
from textual.binding import Binding
from textual.screen import Screen
from textual.widgets import Header, Static
from textual.widgets._tabs import Tab, Tabs

from pwnproxy.repeater.engine import RepeaterEngine
from pwnproxy.repeater.integration import format_flow_as_raw_request
from pwnproxy.repeater.tui.tab import RepeaterTab
from pwnproxy.core.models import Flow

TAB_COUNTER = 0


class RepeaterScreen(Screen[None]):
    """Main Repeater screen managing multiple RepeaterTab instances."""

    BINDINGS = [
        Binding("ctrl+t", "new_tab", "New Tab"),
        Binding("ctrl+w", "close_tab", "Close Tab"),
        Binding("escape", "close_screen", "Close"),
    ]

    def __init__(self, engine: Optional[RepeaterEngine] = None, initial_flow: Optional[Flow] = None):
        super().__init__()
        self._engine = engine or RepeaterEngine()
        self._tabs: dict[str, RepeaterTab] = {}
        self._tab_counter = 0
        self._initial_flow = initial_flow

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Tabs(id="repeater-tabs")
        yield Static("No tabs open. Press Ctrl+T to create a new tab.", id="repeater-empty")

    def on_mount(self) -> None:
        tabs = self.query_one("#repeater-tabs", Tabs)
        tabs.can_focus = False
        if self._initial_flow:
            self.add_tab_for_flow(self._initial_flow)

    def action_new_tab(self) -> None:
        self._add_tab()

    def add_tab_for_flow(self, flow: Flow) -> None:
        raw = format_flow_as_raw_request(flow)
        self._add_tab(raw)

    def _add_tab(self, raw_text: str = "") -> None:
        global TAB_COUNTER
        TAB_COUNTER += 1
        tab_id = f"rep-{TAB_COUNTER}"

        tabs = self.query_one("#repeater-tabs", Tabs)
        tabs.add_tab(Tab(f"Tab {TAB_COUNTER}", id=tab_id))

        tab_widget = RepeaterTab(
            title=f"Tab {TAB_COUNTER}",
            initial_text=raw_text,
            engine=self._engine,
            id=f"{tab_id}-content",
        )
        self._tabs[tab_id] = tab_widget
        self.mount(tab_widget)
        tabs.active = tab_id
        self._show_tab(tab_id)

    def _show_tab(self, tab_id: str) -> None:
        empty = self.query_one("#repeater-empty", Static)
        for tid, widget in self._tabs.items():
            widget.display = tid == tab_id
        empty.display = not bool(self._tabs)

    def on_tabs_tab_activated(self, event: Tabs.TabActivated) -> None:
        tab_id = str(event.tab.id)
        if tab_id in self._tabs:
            self._show_tab(tab_id)

    def action_close_tab(self) -> None:
        tabs = self.query_one("#repeater-tabs", Tabs)
        active = tabs.active
        if active and active in self._tabs:
            widget = self._tabs.pop(active)
            widget.remove()
            tabs.remove_tab(active)
            if self._tabs:
                remaining = list(self._tabs.keys())
                tabs.active = remaining[-1]
                self._show_tab(remaining[-1])
            else:
                self._show_tab("")

    def action_close_screen(self) -> None:
        self.app.pop_screen()
