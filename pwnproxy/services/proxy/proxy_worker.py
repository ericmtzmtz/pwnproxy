import argparse
import asyncio
import json
import logging
import os
import signal
import sys
from pathlib import Path
from typing import Optional

from mitmproxy.options import Options
from mitmproxy.tools.dump import DumpMaster

from pwnproxy.services.proxy.addons.storage import StorageAddon
from pwnproxy.shared.bus.transports.tcp_bridge import TcpBridgeServer
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
    args = p.parse_args()
    logging.info(
        f"Worker started with: db_path={args.db_path}, scope_enabled={args.scope_enabled}, scope_patterns={args.scope_pattern}"
    )
    return args


class ProxyWorker:
    """Runs mitmproxy as a subprocess, controlled by the API."""

    def __init__(self, args: argparse.Namespace):
        self._args = args
        self._master: Optional[DumpMaster] = None
        self._task: Optional[asyncio.Task] = None
        self._bridge = TcpBridgeServer()
        self._running = False

    async def start(self) -> None:
        # Start TCP bridge server
        await self._bridge.start()
        print(f"EVENT_PORT={self._bridge.port}", flush=True)

        opts = Options(
            listen_host=self._args.listen_host,
            listen_port=self._args.listen_port,
            ssl_insecure=self._args.ssl_insecure,
            mode=[f"upstream:{self._args.upstream}"] if self._args.upstream else ["regular"],
        )
        self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
        import os as _os
        opts.update(confdir=_os.path.expanduser(self._args.confdir))

        class BridgeRelay:
            def __init__(self, bridge: TcpBridgeServer):
                self._bridge = bridge

            def request(self, f):
                flow = Flow.from_mitmproxy(f)
                asyncio.create_task(self._bridge.publish("proxy.flow", flow.to_dict()))

            def response(self, f):
                flow = Flow.from_mitmproxy(f)
                asyncio.create_task(self._bridge.publish("proxy.flow", flow.to_dict()))

            def error(self, f):
                flow = Flow.from_mitmproxy(f)
                asyncio.create_task(self._bridge.publish("proxy.flow", flow.to_dict()))

        self._master.addons.add(BridgeRelay(self._bridge))

        if self._args.db_path:
            from sqlalchemy.ext.asyncio import create_async_engine

            engine = create_async_engine(f"sqlite+aiosqlite:///{self._args.db_path}")
            self._master.addons.add(
                StorageAddon(
                    db_engine=engine,
                    scope_filter=self._scope_check,
                    capture_enabled_fn=lambda: self._args.capture_enabled,
                )
            )

        logger.info(
            f"Starting proxy on {self._args.listen_host}:{self._args.listen_port}"
        )
        self._running = True
        self._task = asyncio.create_task(self._run_master())

    def _scope_check(self, flow: "Flow") -> bool:
        if not self._args.scope_enabled or not self._args.scope_pattern:
            return True
        from fnmatch import fnmatch
        for pattern in self._args.scope_pattern:
            if fnmatch(flow.url, pattern):
                return True
        return False

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
        await self._bridge.stop()


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
