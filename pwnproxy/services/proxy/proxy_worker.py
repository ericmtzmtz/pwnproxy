import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Optional

from aiohttp import web
from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from pwnproxy.services.proxy.addons.hook_relay import HookRelayAddon
from pwnproxy.services.proxy.addons.storage import StorageAddon
from pwnproxy.shared.models import Flow

logger = logging.getLogger("proxy_worker")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="pwnproxy worker process")
    p.add_argument("--listen-host", default="127.0.0.1")
    p.add_argument("--listen-port", type=int, default=8080)
    p.add_argument("--ssl-insecure", action="store_true", default=True)
    p.add_argument("--upstream", default=None)
    p.add_argument("--capture-enabled", action="store_true", default=True)
    p.add_argument("--db-path", default=None)
    p.add_argument("--scope-pattern", action="append", default=[])
    p.add_argument("--scope-enabled", action="store_true", default=False)
    p.add_argument("--confdir", default="~/.mitmproxy")
    return p.parse_args()


class EventServer:
    """Local TCP server that receives events from addons and forwards to the API."""

    def __init__(self):
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self._port: int = 0
        self._event_queue: asyncio.Queue = asyncio.Queue()
        self._api_connected = asyncio.Event()

    @property
    def port(self) -> int:
        return self._port

    async def start(self) -> None:
        app = web.Application()
        app.router.add_post("/event", self._handle_event)
        self._runner = web.AppRunner(app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, "127.0.0.1", 0)
        await self._site.start()
        _, self._port = self._site._server.sockets[0].getsockname()
        logger.info(f"Event server listening on port {self._port}")

    async def stop(self) -> None:
        if self._runner:
            await self._runner.cleanup()

    async def _handle_event(self, request: web.Request) -> web.Response:
        body = await request.json()
        await self._event_queue.put(body)
        return web.Response(status=200)

    async def forward_events(self, writer: asyncio.StreamWriter) -> None:
        while True:
            event = await self._event_queue.get()
            line = json.dumps(event) + "\n"
            writer.write(line.encode())
            try:
                await writer.drain()
            except ConnectionResetError:
                logger.warning("API connection lost")
                break


class ProxyWorker:
    """Runs mitmproxy as a subprocess, controlled by the API."""

    def __init__(self, args: argparse.Namespace):
        self._args = args
        self._master: Optional[DumpMaster] = None
        self._task: Optional[asyncio.Task] = None
        self._event_server = EventServer()
        self._running = False

    async def start(self) -> None:
        await self._event_server.start()
        print(f"EVENT_PORT={self._event_server.port}", flush=True)

        opts = Options(
            listen_host=self._args.listen_host,
            listen_port=self._args.listen_port,
            ssl_insecure=self._args.ssl_insecure,
            mode=[f"upstream:{self._args.upstream}"] if self._args.upstream else ["regular"],
        )
        self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        import os as _os
        opts.update(confdir=_os.path.expanduser(self._args.confdir))

        def _publish(event_type: str, flow: Flow) -> None:
            payload = {"type": event_type, "data": flow.to_dict()}
            asyncio.create_task(self._post_event(payload))

        from pwnproxy.services.proxy.addons.hook_relay import HookRelayAddon

        class WorkerHookRelay:
            def __init__(self, publish_fn):
                self._publish = publish_fn
            def request(self, f):
                self._publish("request", Flow.from_mitmproxy(f))
            def response(self, f):
                f = Flow.from_mitmproxy(f)
                self._publish("response", f)
                self._publish("done", f)
            def error(self, f):
                self._publish("error", Flow.from_mitmproxy(f))

        self._master.addons.add(WorkerHookRelay(_publish))
        if self._args.db_path:
            from sqlalchemy import create_engine
            engine = create_engine(f"sqlite:///{self._args.db_path}")
            self._master.addons.add(StorageAddon(
                db_engine=engine,
                scope_filter=self._scope_check,
                capture_enabled_fn=lambda: self._args.capture_enabled,
            ))

        logger.info(f"Starting proxy on {self._args.listen_host}:{self._args.listen_port}")
        self._running = True
        self._task = asyncio.create_task(self._run_master())

    def _scope_check(self, url: str) -> bool:
        if not self._args.scope_enabled or not self._args.scope_pattern:
            return True
        from fnmatch import fnmatch
        for pattern in self._args.scope_pattern:
            if fnmatch(url, pattern):
                return True
        return False

    async def _post_event(self, payload: dict) -> None:
        try:
            async with aiohttp.ClientSession() as session:
                await session.post(
                    f"http://127.0.0.1:{self._event_server.port}/event",
                    json=payload,
                    timeout=aiohttp.ClientTimeout(total=1),
                )
        except Exception:
            pass

    async def _run_master(self) -> None:
        try:
            await self._master.run()
        except SystemExit:
            pass

    async def stop(self) -> None:
        self._running = False
        if self._master:
            self._master.shutdown()
            self._master = None
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except (asyncio.CancelledError, Exception):
                pass
        await self._event_server.stop()


async def main():
    args = _parse_args()
    logging.basicConfig(level=logging.INFO)

    worker = ProxyWorker(args)

    def _shutdown():
        asyncio.create_task(worker.stop())

    if sys.platform != "win32":
        loop = asyncio.get_running_loop()
        loop.add_signal_handler(signal.SIGTERM, _shutdown)
        loop.add_signal_handler(signal.SIGINT, _shutdown)
    else:
        signal.signal(signal.SIGTERM, lambda s, f: asyncio.create_task(worker.stop()))
        signal.signal(signal.SIGINT, lambda s, f: asyncio.create_task(worker.stop()))

    await worker.start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
