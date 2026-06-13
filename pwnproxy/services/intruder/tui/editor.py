from textual.widgets import TextArea


class IntruderEditor(TextArea):
    """Text area for editing raw HTTP requests with §marker§ syntax."""

    def __init__(self, text: str = "", **kwargs):
        super().__init__(text=text, **kwargs)
        self.language = "http"
