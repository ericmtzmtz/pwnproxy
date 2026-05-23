from textual.app import ComposeResult
from textual.containers import Vertical
from textual.widgets import Button, Input, Label, Select, Static


class IntruderConfig(Vertical):
    """Sidebar for attack configuration."""

    def compose(self) -> ComposeResult:
        yield Static("[bold]Attack Mode[/]", classes="section-label")
        yield Select(
            [("Sniper", "sniper"), ("Cluster Bomb", "cluster_bomb")],
            prompt="Mode",
            id="attack-mode",
            value="sniper",
        )

        yield Static("[bold]Concurrency[/]", classes="section-label")
        yield Input(value="10", id="concurrency", type="integer", placeholder="Requests at once")

        yield Static("[bold]Wordlist[/]", classes="section-label")
        yield Input(value="", id="wordlist-path", placeholder="Path to wordlist file")
        yield Button("Browse", id="btn-browse", variant="default")
        yield Static("", id="wordlist-info")

        yield Static("[bold]Payloads per marker[/]", id="payload-count")
        yield Button("Start Attack", id="btn-start", variant="primary")
        yield Button("Stop", id="btn-stop", variant="error", disabled=True)

    def set_wordlist_info(self, count: int) -> None:
        self.query_one("#wordlist-info", Static).update(f"[green]{count} lines loaded[/]")
