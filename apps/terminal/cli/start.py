import asyncio
import json
import logging
import signal
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Prompt

from apps.api.server import start_api_server
from pwnproxy.shared.db import create_engine as create_traffic_engine, init_db
from pwnproxy.services.proxy.proxy_process import ProxyProcess
from pwnproxy.shared.hooks import HookBus
from pwnproxy.shared.bus.transports.inprocess import InProcessBus

logger = logging.getLogger(__name__)
console = Console()


async def _interactive_session_prompt(session_manager) -> str | None:
    sessions = session_manager.list()
    has_sessions = len(sessions) > 0

    if has_sessions:
        choices = "1"
        prompt_text = "[1] Resume last session"
        last = await session_manager._read_last_session()
        if last and any(s["name"] == last for s in sessions):
            prompt_text += f" [dim]({last})[/]"
        options = "[1] Resume  [2] Browse all sessions  [3] New session  [q] Quit"

        if len(sessions) >= 2:
            choices += "23"
        else:
            options = "[1] Browse all sessions  [2] New session  [q] Quit"
            choices = "12"

        console.print(Panel(prompt_text, title="[bold]Session[/]"))
        answer = Prompt.ask(options, choices=list(choices) + ["q"], default="1")

        if answer == "q":
            return "__quit__"
        if answer == "3" or (answer == "2" and len(sessions) < 2):
            name = Prompt.ask("Session name")
            if name.strip():
                try:
                    await session_manager.create(name.strip())
                    return None
                except ValueError:
                    console.print(f"[red]Session '{name}' already exists[/]")
                    return await _interactive_session_prompt(session_manager)
            return await _interactive_session_prompt(session_manager)
        if answer == "2" and len(sessions) >= 2:
            console.print("\n[bold]Available sessions:[/]")
            for i, s in enumerate(sessions, 1):
                modified = (s.get("last_modified") or "")[:19]
                console.print(f"  {i}. {s['name']} [dim]({modified})[/]")
            num = Prompt.ask(
                "Enter number to load, [n] New session, [q] Quit",
                choices=[str(i) for i in range(1, len(sessions) + 1)] + ["n", "q"],
            )
            if num == "q":
                return "__quit__"
            if num == "n":
                name = Prompt.ask("Session name")
                if name.strip():
                    try:
                        await session_manager.create(name.strip())
                        return None
                    except ValueError:
                        console.print(f"[red]Session '{name}' already exists[/]")
                        return await _interactive_session_prompt(session_manager)
                return await _interactive_session_prompt(session_manager)
            idx = int(num) - 1
            return sessions[idx]["name"]
        if last and any(s["name"] == last for s in sessions):
            return last
        return sessions[0]["name"]
    else:
        console.print(Panel("[yellow]No sessions found. Create one to get started.[/]", title="[bold]Session[/]"))
        answer = Prompt.ask("[1] Create a new session  [q] Quit", choices=["1", "q"], default="1")
        if answer == "q":
            return "__quit__"
        name = Prompt.ask("Session name")
        if name.strip():
            await session_manager.create(name.strip())
            return None
        return await _interactive_session_prompt(session_manager)


def start(
    host: str = typer.Option("127.0.0.1", "--host", help="Bind address for both proxy and API"),
    proxy_port: int = typer.Option(8080, "--proxy-port", help="Proxy listen port"),
    api_port: int = typer.Option(8000, "--api-port", help="API server port"),
    tui: bool = typer.Option(False, "--tui", help="Launch TUI dashboard"),
    no_tui: bool = typer.Option(False, "--no-tui", help="Run without TUI (default)"),
    upstream: str = typer.Option(None, "--upstream", help="Upstream proxy URL (socks5://host:port or http://host:port)"),
    session: str = typer.Option(None, "--session", help="Load an existing session on boot"),
    session_name: str = typer.Option(None, "--session-name", help="Create and activate a new session on boot"),
    no_restore_session: bool = typer.Option(False, "--no-restore-session", help="Start with empty state, do not restore last session"),
    callback_port: int = typer.Option(18081, "--callback-port", help="Port for SSRF callback server"),
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
        bus = InProcessBus()

        def _on_proxy_event(topic: str, data: dict) -> None:
            """Bridge events from proxy worker to HookBus (PluginLoader consumers)."""
            if topic == "proxy.flow":
                from pwnproxy.shared.models import Flow
                flow = Flow.from_dict(data)
                hook_bus.publish("flow", flow)
            else:
                hook_bus.publish(topic, data)

        traffic_engine = create_traffic_engine()
        await init_db(traffic_engine)

        from apps.api.server import _create_scanner_engine
        scanner_engine = _create_scanner_engine()

        from pwnproxy.services.session.storage import TokenStorage
        token_storage = TokenStorage()
        await token_storage.init()

        from pwnproxy.services.session.consumer import SessionConsumer
        session_consumer = SessionConsumer(hook_bus, token_storage)
        await session_consumer.start()

        from pwnproxy.services.session.manager import SessionManager
        session_manager = SessionManager(
            traffic_engine=traffic_engine,
            scanner_engine=scanner_engine,
            token_storage=token_storage,
        )

        scope_check = lambda flow: session_manager.scope.is_in_scope(flow.url)
        proxy = ProxyProcess()
        session_manager.set_proxy_engine(proxy)
        proxy.set_event_callback(_on_proxy_event)

        # ── Interceptor controller (must be created before session ops) ──
        from pwnproxy.services.proxy.interceptor.addon import InterceptorAddon
        from pwnproxy.services.proxy.interceptor.controller import InterceptorController
        intercept_queue: asyncio.Queue = asyncio.Queue()
        intercept_addon = InterceptorAddon(intercept_queue, scope_filter=lambda url: True)
        interceptor_controller = InterceptorController(intercept_addon, on_intercepted=lambda f: None)
        interceptor_controller.start()
        session_manager.set_module_providers(interceptor_controller=interceptor_controller)

        # ── Session operations ──
        prompted = False
        if not session and not session_name and not no_restore_session and not tui:
            chosen = await _interactive_session_prompt(session_manager)
            if chosen == "__quit__":
                console.print("[yellow]Exiting.[/]")
                return
            prompted = True
            if not chosen:
                await session_manager._ensure_lazy()

        if not prompted:
            if no_restore_session:
                session_manager._active_name = "default"
                session_manager._active_path = Path.home() / ".pwnproxy" / "sessions" / "default"
                await session_manager._point_engines(session_manager._active_path)
            else:
                await session_manager.start()
        if session_name:
            await session_manager.create(session_name)
        elif session:
            await session_manager.load(session)
        elif prompted and chosen and chosen != "__quit__":
            await session_manager.load(chosen)

        traffic_engine = session_manager.get_traffic_engine()
        scanner_engine = session_manager.get_scanner_engine()
        token_storage = session_manager.get_token_storage()

        hook_bus.set_scope_filter(scope_check)
        intercept_addon.set_scope_filter(session_manager.scope.is_in_scope)

        from pwnproxy.services.intruder.engine import IntruderEngine
        from pwnproxy.services.repeater.engine import RepeaterEngine
        intruder_engine = IntruderEngine()
        repeater_engine = RepeaterEngine()

        if upstream:
            valid_schemes = ("http://", "https://", "socks5://")
            if not upstream.lower().startswith(valid_schemes):
                console.print("[bold red]ERROR:[/] Invalid upstream URL scheme")
                console.print(f"[yellow]Supported schemes: {', '.join(valid_schemes)}[/]")
                raise typer.Exit(1)

        from pwnproxy.plugins.core.loader import PluginLoader
        from pwnproxy.plugins.scanners.sqli.plugin import SQLiScannerPlugin
        from pwnproxy.plugins.scanners.xss.plugin import XSSScannerPlugin
        from pwnproxy.plugins.scanners.lfi.plugin import LFIScannerPlugin
        from pwnproxy.plugins.scanners.xxe.plugin import XXEScannerPlugin
        from pwnproxy.plugins.scanners.ssrf.plugin import SSRFScannerPlugin
        plugin_loader = PluginLoader(hook_bus=hook_bus)
        await plugin_loader.load_builtin(SQLiScannerPlugin())
        await plugin_loader.load_builtin(XSSScannerPlugin())
        await plugin_loader.load_builtin(LFIScannerPlugin())
        await plugin_loader.load_builtin(XXEScannerPlugin())
        await plugin_loader.load_builtin(SSRFScannerPlugin())
        session_manager.set_module_providers(plugin_loader=plugin_loader)
        # Wire PluginLoader with SessionManager and start it
        plugin_loader._session_manager = session_manager
        await plugin_loader.start()

        api_task = await start_api_server(
            hook_bus=hook_bus,
            traffic_engine=traffic_engine,
            scanner_engine=scanner_engine,
            repeater_engine=repeater_engine,
            intruder_engine=intruder_engine,
            interceptor_controller=interceptor_controller,
            token_storage=token_storage,
            session_manager=session_manager,
            plugin_loader=plugin_loader,
            proxy_engine=proxy,
            host=host,
            port=api_port,
            proxy_port=proxy_port,
        )

        shutdown_event = asyncio.Event()

        def _on_sigint():
            shutdown_event.set()
        if sys.platform != "win32":
            try:
                loop = asyncio.get_running_loop()
                loop.add_signal_handler(signal.SIGINT, _on_sigint)
                loop.add_signal_handler(signal.SIGTERM, _on_sigint)
            except NotImplementedError:
                pass
        else:
            signal.signal(signal.SIGINT, lambda s, f: shutdown_event.set())
            signal.signal(signal.SIGTERM, lambda s, f: shutdown_event.set())

        dashboard_task = None
        if tui:
            from apps.terminal.tui.app import DashboardApp

            ws_host = "127.0.0.1"
            dashboard = DashboardApp(
                host=ws_host,
                api_port=api_port,
                hook_bus=hook_bus,
                interceptor_controller=interceptor_controller,
                scan_manager=scan_manager,
            )
            dashboard_task = asyncio.create_task(dashboard.run_async())

        err_console = Console(stderr=True)
        panel_lines = [
            f"[green]Session:[/] {session_manager.active_name or '[dim](none)[/]'}",
            f"[green]Proxy    →[/] [bold]http://{host}:{proxy_port}[/]",
            f"[green]API      →[/] [bold]http://{host}:{api_port}[/]",
            f"[green]API Docs →[/] [bold]http://{host}:{api_port}/docs[/]",
        ]
        if tui:
            panel_lines.append(f"[green]Web UI   →[/] [bold]http://127.0.0.1:4321[/]")
        if upstream:
            panel_lines.append(f"[cyan]Upstream:[/] {upstream}")
        if dashboard_task:
            panel_lines.append(f"[green]TUI dashboard[/] launched (press Q or Ctrl+Q to quit)")
        else:
            panel_lines.append("[dim]Press Ctrl+C to stop[/]")
        err_console.print(Panel("\n".join(panel_lines), title="[bold]pwnproxy[/]"))

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
        await proxy.stop()
        interceptor_controller.stop()
        await plugin_loader.shutdown()
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
