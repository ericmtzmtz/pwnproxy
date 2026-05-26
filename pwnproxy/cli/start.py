import asyncio
import logging
from pathlib import Path

import typer
from rich.console import Console

from pwnproxy.api.server import start_api_server
from pwnproxy.core.db import create_engine as create_traffic_engine, init_db
from pwnproxy.core.engine import ProxyEngine
from pwnproxy.core.hooks import HookBus

logger = logging.getLogger(__name__)
console = Console()


def start(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address for both proxy and API"),
    proxy_port: int = typer.Option(8080, "--proxy-port", help="Proxy listen port"),
    api_port: int = typer.Option(8000, "--api-port", help="API server port"),
    tui: bool = typer.Option(False, "--tui", help="Launch TUI dashboard"),
    upstream: str = typer.Option(None, "--upstream", help="Upstream proxy URL (socks5://host:port or http://host:port)"),
    session: str = typer.Option(None, "--session", help="Load an existing session on boot"),
    session_name: str = typer.Option(None, "--session-name", help="Create and activate a new session on boot"),
    no_restore_session: bool = typer.Option(False, "--no-restore-session", help="Start with empty state, do not restore last session"),
):
    async def _run():
        # Reconfigure logging based on mode
        for h in logging.root.handlers[:]:
            logging.root.removeHandler(h)

        if tui:
            log_file = Path.home() / ".pwnproxy" / "proxy.log"
            log_file.parent.mkdir(parents=True, exist_ok=True)
            logging.basicConfig(
                filename=str(log_file),
                level=logging.INFO,
                format="%(asctime)s %(name)s %(message)s",
                force=True,
            )
            logging.getLogger("mitmproxy").setLevel(logging.WARNING)
            logging.getLogger("uvicorn").setLevel(logging.WARNING)
        else:
            logging.basicConfig(
                level=logging.INFO,
                format="%(levelname)s:%(name)s:%(message)s",
                force=True,
            )
        hook_bus = HookBus()

        traffic_engine = create_traffic_engine()
        await init_db(traffic_engine)

        from pwnproxy.api.server import _create_scanner_engine
        scanner_engine = _create_scanner_engine()

        from pwnproxy.modules.session_manager.storage import TokenStorage
        token_storage = TokenStorage()
        await token_storage.init()

        from pwnproxy.modules.session_manager.consumer import SessionConsumer
        session_consumer = SessionConsumer(hook_bus, token_storage)
        await session_consumer.start()

        from pwnproxy.modules.session_manager.manager import SessionManager
        session_manager = SessionManager(
            traffic_engine=traffic_engine,
            scanner_engine=scanner_engine,
            token_storage=token_storage,
        )
        if no_restore_session:
            session_manager._active_name = "default"
            session_manager._active_path = Path.home() / ".pwnproxy" / "sessions" / "default"
        else:
            await session_manager.start()

        if session_name:
            await session_manager.create(session_name)
        elif session:
            await session_manager.load(session)

        traffic_engine = session_manager.get_traffic_engine()
        scanner_engine = session_manager.get_scanner_engine()
        token_storage = session_manager.get_token_storage()

        scope_check = lambda flow: session_manager.scope.is_in_scope(flow.url)
        hook_bus.set_scope_filter(scope_check)

        from pwnproxy.intruder.engine import IntruderEngine
        from pwnproxy.repeater.engine import RepeaterEngine
        intruder_engine = IntruderEngine()
        repeater_engine = RepeaterEngine()

        if upstream:
            valid_schemes = ("http://", "https://", "socks5://")
            if not upstream.lower().startswith(valid_schemes):
                console.print("[bold red]ERROR:[/] Invalid upstream URL scheme")
                console.print(f"[yellow]Supported schemes: {', '.join(valid_schemes)}[/]")
                raise typer.Exit(1)

        proxy = ProxyEngine(hook_bus=hook_bus, db_engine=traffic_engine, with_termlog=not tui, upstream=upstream, scope_filter=scope_check)
        await proxy.start(host=host, port=proxy_port)

        await asyncio.sleep(0.3)

        if proxy._task.done():
            console.print(f"\n[bold red]ERROR:[/] Failed to start proxy on [bold]{host}:{proxy_port}[/]")
            console.print("[yellow]Make sure the port is available and not in use.[/]")
            console.print("[yellow]Try:[/] [bold]--proxy-port PORT[/]")
            await asyncio.gather(
                traffic_engine.dispose(),
                scanner_engine.dispose(),
                return_exceptions=True,
            )
            raise typer.Exit(1)

        from pwnproxy.modules.interceptor.addon import InterceptorAddon
        from pwnproxy.modules.interceptor.controller import InterceptorController
        intercept_queue: asyncio.Queue = asyncio.Queue()
        intercept_addon = InterceptorAddon(intercept_queue, scope_filter=session_manager.scope.is_in_scope)
        await proxy.register_addon(intercept_addon)
        interceptor_controller = InterceptorController(intercept_addon, on_intercepted=lambda f: None)
        interceptor_controller.start()

        from pwnproxy.scanners.sqli.scanner import SQLiScanner
        from pwnproxy.scanners.xss.scanner import XSSScanner
        from pwnproxy.scanners.lfi.scanner import LFIScanner
        from pwnproxy.scanners.xxe.scanner import XXEScanner
        from pwnproxy.scanners.ssrf.scanner import SSRFScanner
        from pwnproxy.scanners.sqli.storage import FindingStorage as SqliStorage
        from pwnproxy.scanners.xss.storage import XssFindingStorage as XssStorage
        from pwnproxy.scanners.lfi.storage import LfiFindingStorage as LfiStorage
        from pwnproxy.scanners.xxe.storage import XxeFindingStorage as XxeStorage
        from pwnproxy.scanners.ssrf.storage import SsrfFindingStorage as SsrfStorage
        from pwnproxy.scanners.common.scan_log_store import ScanLogStore
        from pwnproxy.scanners.common.manager import ScanManager
        session_path = session_manager._active_path
        scanner_db = str(session_path / "scanner_results.db")
        scan_log_store = ScanLogStore(db_path=scanner_db)
        await scan_log_store.create_table()
        scan_manager = ScanManager(
            sqli=SQLiScanner(hook_bus, storage=SqliStorage(db_path=scanner_db)),
            xss=XSSScanner(hook_bus, storage=XssStorage(db_path=scanner_db)),
            lfi=LFIScanner(hook_bus, storage=LfiStorage(db_path=scanner_db)),
            xxe=XXEScanner(hook_bus, storage=XxeStorage(db_path=scanner_db)),
            ssrf=SSRFScanner(hook_bus, storage=SsrfStorage(db_path=scanner_db)),
            scan_log_store=scan_log_store,
        )
        # Scanners start OFF — enabled via Scanner tab toggles

        api_task = await start_api_server(
            hook_bus=hook_bus,
            traffic_engine=traffic_engine,
            scanner_engine=scanner_engine,
            repeater_engine=repeater_engine,
            intruder_engine=intruder_engine,
            interceptor_controller=interceptor_controller,
            token_storage=token_storage,
            session_manager=session_manager,
            host=host,
            port=api_port,
        )

        shutdown_event = asyncio.Event()

        dashboard_task = None
        if tui:
            from pwnproxy.tui.app import DashboardApp

            ws_host = "127.0.0.1"
            dashboard = DashboardApp(
                host=ws_host,
                api_port=api_port,
                hook_bus=hook_bus,
                interceptor_controller=interceptor_controller,
                scan_manager=scan_manager,
            )
            dashboard_task = asyncio.create_task(dashboard.run_async())

        console.print(f"[green]Session:[/] {session_manager.active_name}")
        console.print(f"[green]Proxy[/] listening on [bold]{host}:{proxy_port}[/]")
        console.print(f"[green]API[/] listening on [bold]{host}:{api_port}[/]")
        if upstream:
            console.print(f"[cyan]Upstream:[/] {upstream}")
        if dashboard_task:
            console.print(f"[green]TUI dashboard[/] launched (press Q or Ctrl+Q to quit)")
        else:
            console.print("[dim]Press Ctrl+C to stop[/]")

        try:
            if dashboard_task:
                shutdown_task = asyncio.create_task(shutdown_event.wait())
                await asyncio.wait(
                    [shutdown_task, dashboard_task],
                    return_when=asyncio.FIRST_COMPLETED,
                )
            else:
                await shutdown_event.wait()
        except asyncio.CancelledError:
            pass

        console.print("\n[bold yellow]Shutting down...[/]")
        proxy.stop()
        interceptor_controller.stop()
        await scan_manager.dispose()
        await session_consumer.stop()
        await session_manager.stop()
        api_task.cancel()
        if dashboard_task:
            dashboard_task.cancel()

        await asyncio.gather(
            traffic_engine.dispose(),
            scanner_engine.dispose(),
            api_task,
            return_exceptions=True,
        )

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        pass
