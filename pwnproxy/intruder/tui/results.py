from typing import Optional

from textual.message import Message
from textual.widgets import DataTable


class IntruderResults(DataTable):
    class AddResults(Message):
        def __init__(self, results: list[dict]) -> None:
            self.results = results
            super().__init__()

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self._can_focus = False

    def on_mount(self) -> None:
        self.add_columns("#", "Payload", "Status", "Length", "Time (ms)", "Error")

    def on_intruder_results_add_results(self, event: AddResults) -> None:
        self.clear()
        self.add_columns("#", "Payload", "Status", "Length", "Time (ms)", "Error")
        for r in event.results:
            status = r.get("status_code", "")
            status_str = f"[green]{status}[/]" if status and status < 500 else f"[red]{status}[/]" if status else "[grey]ERR[/]"
            err = r.get("error") or ""
            err_display = f"[red]{err[:20]}[/]" if err else ""
            self.add_row(
                str(r.get("request_id", "")),
                (r.get("payload", "") or "")[:30],
                status_str,
                str(r.get("response_length", "")),
                str(r.get("timing_ms", "")),
                err_display,
            )
