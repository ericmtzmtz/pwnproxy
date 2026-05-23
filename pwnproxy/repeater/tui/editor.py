from textual.widgets import TextArea


class RequestEditor(TextArea):
    """Text area for editing raw HTTP requests."""

    def __init__(self, text: str = "", **kwargs):
        super().__init__(text=text, **kwargs)
        self.language = "http"
