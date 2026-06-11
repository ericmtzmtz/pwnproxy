"""HTTP callback server for OOB vulnerability confirmation."""
import asyncio
import logging
import os
from typing import Optional

from aiohttp import web

from pwnproxy.oob.canary import get_registry

logger = logging.getLogger(__name__)

DEFAULT_PORT = int(os.environ.get("PWNPROXY_OOB_PORT", "8888"))
DEFAULT_HOST = os.environ.get("PWNPROXY_OOB_HOST", "0.0.0.0")


class HTTPCallbackServer:
    """HTTP server that logs incoming callback requests.
    
    When a blind vulnerability is confirmed, the target makes an HTTP
    request to this server with the canary token in the URL or headers.
    """
    
    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
    ):
        self.host = host
        self.port = port
        self._app: Optional[web.Application] = None
        self._runner: Optional[web.AppRunner] = None
        self._site: Optional[web.TCPSite] = None
        self._running = False
    
    async def start(self) -> None:
        """Start the HTTP callback server."""
        if self._running:
            return
        
        self._app = web.Application()
        self._app.router.add_route("*", "/{token:.*}", self._handle_callback)
        self._app.router.add_route("*", "/", self._handle_root)
        
        self._runner = web.AppRunner(self._app)
        await self._runner.setup()
        self._site = web.TCPSite(self._runner, self.host, self.port)
        await self._site.start()
        
        self._running = True
        logger.info("OOB HTTP callback server started on %s:%d", self.host, self.port)
    
    async def stop(self) -> None:
        """Stop the HTTP callback server."""
        if not self._running:
            return
        
        if self._runner:
            await self._runner.cleanup()
        
        self._running = False
        logger.info("OOB HTTP callback server stopped")
    
    async def _handle_root(self, request: web.Request) -> web.Response:
        """Handle requests to root path."""
        return web.Response(
            text="pwnproxy OOB callback server",
            content_type="text/plain",
        )
    
    async def _handle_callback(self, request: web.Request) -> web.Response:
        """Handle incoming callback requests.
        
        The canary token is expected in the URL path:
        GET /<token>
        """
        token = request.match_info.get("token", "")
        
        # Extract client IP
        peername = request.transport.get_extra_info("peername")
        client_ip = peername[0] if peername else "unknown"
        
        # Collect headers
        headers = dict(request.headers)
        
        # Mark canary as confirmed
        registry = get_registry()
        confirmed = registry.mark_callback(token, client_ip, headers)
        
        if confirmed:
            logger.info(
                "OOB callback confirmed: token=%s ip=%s path=%s",
                token,
                client_ip,
                request.path,
            )
            return web.Response(
                text="OK",
                status=200,
            )
        else:
            logger.warning(
                "OOB callback for unknown/expired token: %s from %s",
                token,
                client_ip,
            )
            return web.Response(
                text="Not Found",
                status=404,
            )
    
    @property
    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running
    
    def get_callback_url(self, token: str) -> str:
        """Get the callback URL for a canary token.
        
        Args:
            token: The canary token
            
        Returns:
            Full callback URL
        """
        return f"http://{self.host}:{self.port}/{token}"


# Global server instance
_server: Optional[HTTPCallbackServer] = None


async def get_server() -> HTTPCallbackServer:
    """Get the global HTTP callback server instance."""
    global _server
    if _server is None:
        _server = HTTPCallbackServer()
    return _server


async def start_server() -> HTTPCallbackServer:
    """Start the global HTTP callback server."""
    server = await get_server()
    await server.start()
    return server


async def stop_server() -> None:
    """Stop the global HTTP callback server."""
    global _server
    if _server and _server.is_running:
        await _server.stop()
