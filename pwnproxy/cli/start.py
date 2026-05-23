import asyncio
import logging
import signal

import typer
from rich.console import Console

from pwnproxy.api.server import start_api_server
from pwnproxy.core.db import create_engine as create_traffic_engine, init_db
from pwnproxy.core.engine import ProxyEngine
from pwnproxy.core.hooks import HookBus

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")
logger = logging.getLogger(__name__)
console = Console()


def start(
    proxy_port: int = typer.Option(8080, "--proxy-port", help="Proxy listen port"),
    api_port: int = typer.Option(8000, "--api-port", help="API server port"),
):
    async def _run():
        hook_bus = HookBus()

        traffic_engine = create_traffic_engine()
        await init_db(traffic_engine)

        from pwnproxy.api.server import _create_scanner_engine, _create_sessions_engine
        scanner_engine = _create_scanner_engine()
        sessions_engine = _create_sessions_engine()

        proxy = ProxyEngine(hook_bus=hook_bus, db_engine=traffic_engine)
        await proxy.start(host="127.0.0.1", port=proxy_port)

        await asyncio.sleep(0.3)

        if proxy._task.done():
            console.print(f"\n[bold red]ERROR:[/] Failed to start proxy on [bold]127.0.0.1:{proxy_port}[/]")
            console.print("[yellow]Make sure the port is available and not in use.[/]")
            console.print("[yellow]Try:[/] [bold]--proxy-port PORT[/]")
            await asyncio.gather(
                traffic_engine.dispose(),
                scanner_engine.dispose(),
                sessions_engine.dispose(),
                return_exceptions=True,
            )
            raise typer.Exit(1)

        api_task = await start_api_server(
            hook_bus=hook_bus,
            traffic_engine=traffic_engine,
            scanner_engine=scanner_engine,
            host="127.0.0.1",
            port=api_port,
        )

        shutdown_event = asyncio.Event()

        def _handle_signal():
            console.print("\n[bold yellow]Shutting down...[/]")
            proxy.stop()
            api_task.cancel()
            shutdown_event.set()

        loop = asyncio.get_event_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, _handle_signal)
            except (ValueError, NotImplementedError):
                pass

        console.print(f"[green]Proxy[/] listening on [bold]127.0.0.1:{proxy_port}[/]")
        console.print(f"[green]API[/] listening on [bold]127.0.0.1:{api_port}[/]")
        console.print("[dim]Press Ctrl+C to stop[/]")

        await shutdown_event.wait()

        await asyncio.gather(
            traffic_engine.dispose(),
            scanner_engine.dispose(),
            sessions_engine.dispose(),
            return_exceptions=True,
        )

    asyncio.run(_run())
