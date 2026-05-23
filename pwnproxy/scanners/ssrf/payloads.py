import uuid
from dataclasses import dataclass


@dataclass
class SsrfPayload:
    type: str
    value: str
    description: str


class PayloadGenerator:
    def __init__(self, callback_host: str = "127.0.0.1", callback_port: int = 8080):
        self.callback_host = callback_host
        self.callback_port = callback_port

    def generate(self) -> SsrfPayload:
        canary = str(uuid.uuid4())
        url = f"http://{self.callback_host}:{self.callback_port}/callback/{canary}"
        return SsrfPayload(type="callback", value=url, description=url)
