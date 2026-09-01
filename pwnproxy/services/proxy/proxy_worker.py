import argparse
from pwnproxy.shared.flow_filter import FlowFilter
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
from pwnproxy.services.session.manager import ScopeConfig
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
    p.add_argument("--scope-json", default=None, help="JSON-encoded ScopeConfig")
    p.add_argument("--scope-enabled", action="store_true", default=False, help="Enable scope filtering")
    p.add_argument("--scope-pattern", action="append", default=[], help="Scope pattern (can be repeated)")
    p.add_argument("--confdir", default="~/.mitmproxy")
    args = p.parse_args()
    scope_info = "none"
    if args.scope_json:
        try:
            sc = json.loads(args.scope_json)
            scope_info = f"enabled={sc.get('enabled')}, in={len(sc.get('in_scope',[]))}, out={len(sc.get('out_of_scope',[]))}"
        except Exception:
            scope_info = "parse-error"
    logging.info(
        f"Worker started with: db_path={args.db_path}, scope={scope_info}"
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
        self._scope_config: Optional[ScopeConfig] = None
        self._flow_filter: Optional[FlowFilter] = None
        self._watch_task: Optional[asyncio.Task] = None
        if args.scope_enabled:
            # Build ScopeConfig from enabled flag and patterns
            data = {"enabled": True, "in_scope": args.scope_pattern or [], "out_of_scope": []}
            self._scope_config = ScopeConfig(data)
        elif args.scope_json:
            try:
                self._scope_config = ScopeConfig(json.loads(args.scope_json))
            except (json.JSONDecodeError, Exception) as e:
                logger.warning(f"Failed to parse --scope-json: {e}")
        # Initialize FlowFilter based on scope config
        self._flow_filter = FlowFilter(self._scope_config) if self._scope_config else FlowFilter(ScopeConfig())

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
            def __init__(self, bridge: TcpBridgeServer, flow_filter: FlowFilter):
                self._bridge = bridge
                self._flow_filter = flow_filter

            def request(self, f):
                if not self._flow_filter.allow(f.request.pretty_url):
                    return
                flow = Flow.from_mitmproxy(f)
                asyncio.create_task(self._bridge.publish("proxy.flow", flow.to_dict()))

            def response(self, f):
                if not self._flow_filter.allow(f.request.pretty_url):
                    return
                flow = Flow.from_mitmproxy(f)
                asyncio.create_task(self._bridge.publish("proxy.flow", flow.to_dict()))

            def error(self, f):
                if not self._flow_filter.allow(f.request.pretty_url):
                    return
                flow = Flow.from_mitmproxy(f)
                asyncio.create_task(self._bridge.publish("proxy.flow", flow.to_dict()))

        self._master.addons.add(BridgeRelay(self._bridge, self._flow_filter))

        if self._args.db_path:
            from sqlalchemy.ext.asyncio import create_async_engine

            engine = create_async_engine(f"sqlite+aiosqlite:///{self._args.db_path}")

            class BridgeHookBus:
                def __init__(self, bridge: TcpBridgeServer):
                    self._bridge = bridge
                def publish(self, channel: str, data: dict) -> None:
                    asyncio.create_task(self._bridge.publish("proxy." + channel, data))

            self._master.addons.add(
                StorageAddon(
                    db_engine=engine,
                    hook_bus=BridgeHookBus(self._bridge),
                    flow_filter=self._flow_filter,
                )
            )

        if sys.platform == "win32":
            self._watch_task = asyncio.create_task(self._watch_scope_file())

        logger.info(
            f"Starting proxy on {self._args.listen_host}:{self._args.listen_port}"
        )
        self._running = True
        self._task = asyncio.create_task(self._run_master())

    def _scope_filter(self, url: str) -> bool:
        if self._scope_config is None:
            return True
        return self._scope_config.is_in_scope(url)

    def reload_scope(self) -> bool:
        """Reload scope configuration from session scope.json without restart."""
        if not self._args.db_path:
            return False
        scope_file = Path(self._args.db_path).parent / "scope.json"
        if not scope_file.exists():
            logger.warning(f"scope.json not found at {scope_file}")
            return False
        try:
            data = json.loads(scope_file.read_text())
            self._scope_config = ScopeConfig(data)
            # Propagate to the live FlowFilter shared by BridgeRelay + StorageAddon.
            self._flow_filter.set_scope(self._scope_config)
            logger.info(f"Scope reloaded: enabled={self._scope_config.enabled}, "
                         f"in={len(self._scope_config.in_scope)}, out={len(self._scope_config.out_of_scope)}")
            return True
        except Exception as e:
            logger.error(f"Failed to reload scope: {e}")
            return False

    async def _watch_scope_file(self) -> None:
        """Periodically check scope.json for changes (Windows fallback)."""
        if not self._args.db_path:
            return
        scope_file = Path(self._args.db_path).parent / "scope.json"
        if not scope_file.exists():
            return
        import os as _os
        try:
            last_mtime = _os.path.getmtime(scope_file)
        except OSError:
            return
        while self._running:
            await asyncio.sleep(1)
            try:
                if scope_file.exists():
                    mtime = _os.path.getmtime(scope_file)
                    if mtime != last_mtime:
                        last_mtime = mtime
                        if self.reload_scope():
                            logger.info("Scope updated via file-watch")
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
        loop.add_signal_handler(signal.SIGUSR1, worker.reload_scope)
    else:
        signal.signal(signal.SIGTERM, lambda s, f: asyncio.create_task(worker.stop()))
        signal.signal(signal.SIGINT, lambda s, f: asyncio.create_task(worker.stop()))

    await worker.start()
    await asyncio.Event().wait()


if __name__ == "__main__":
    asyncio.run(main())
