"""DNS callback server for OOB vulnerability confirmation."""
import asyncio
import logging
import os
import socket
import struct
from typing import Optional

from pwnproxy.shared.canary import get_registry

logger = logging.getLogger(__name__)

DEFAULT_DNS_PORT = int(os.environ.get("PWNPROXY_OOB_DNS_PORT", "53"))
DEFAULT_HOST = os.environ.get("PWNPROXY_OOB_HOST", "0.0.0.0")


class DNSCallbackServer:
    """DNS server that logs incoming DNS queries.
    
    When a blind vulnerability is confirmed, the target makes a DNS
    query for <token>.<domain>. This server logs the query and responds
    with a dummy IP address.
    """
    
    def __init__(
        self,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_DNS_PORT,
        domain: str = "oob.pwnproxy.local",
    ):
        self.host = host
        self.port = port
        self.domain = domain
        self._socket: Optional[socket.socket] = None
        self._running = False
        self._task: Optional[asyncio.Task] = None
    
    async def start(self) -> None:
        """Start the DNS callback server."""
        if self._running:
            return
        
        try:
            # Create UDP socket
            self._socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._socket.bind((self.host, self.port))
            self._socket.setblocking(False)
            
            self._running = True
            self._task = asyncio.create_task(self._serve())
            logger.info("OOB DNS callback server started on %s:%d", self.host, self.port)
        except PermissionError:
            logger.warning(
                "Cannot bind to port %d (permission denied). "
                "DNS callback server disabled. Use sudo or a different port.",
                self.port,
            )
            self._running = False
        except Exception as e:
            logger.error("Failed to start DNS callback server: %s", e)
            self._running = False
    
    async def stop(self) -> None:
        """Stop the DNS callback server."""
        if not self._running:
            return
        
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        if self._socket:
            self._socket.close()
        logger.info("OOB DNS callback server stopped")
    
    async def _serve(self) -> None:
        """Main serve loop."""
        loop = asyncio.get_event_loop()
        while self._running:
            try:
                data, addr = await loop.sock_recvfrom(self._socket, 1024)
                await self._handle_query(data, addr)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("DNS server error: %s", e)
    
    async def _handle_query(self, data: bytes, addr: tuple) -> None:
        """Handle incoming DNS query."""
        try:
            # Parse DNS query
            query = self._parse_dns_query(data)
            if query is None:
                return
            
            qname, qtype, transaction_id = query
            
            # Extract token from qname (e.g., "abc123.oob.pwnproxy.local")
            token = self._extract_token(qname)
            
            # Extract client IP
            client_ip = addr[0]
            
            # Mark canary as confirmed
            registry = get_registry()
            confirmed = registry.mark_callback(token, client_ip, {"dns_query": qname})
            
            if confirmed:
                logger.info(
                    "OOB DNS callback confirmed: token=%s ip=%s query=%s",
                    token,
                    client_ip,
                    qname,
                )
            else:
                logger.debug(
                    "OOB DNS query for unknown/expired token: %s from %s",
                    token,
                    client_ip,
                )
            
            # Send response (dummy A record)
            response = self._build_dns_response(transaction_id, qname)
            self._socket.sendto(response, addr)
            
        except Exception as e:
            logger.error("Error handling DNS query: %s", e)
    
    def _parse_dns_query(self, data: bytes) -> Optional[tuple]:
        """Parse DNS query packet.
        
        Returns:
            Tuple of (qname, qtype, transaction_id) or None if invalid
        """
        if len(data) < 12:
            return None
        
        # Extract transaction ID
        transaction_id = struct.unpack("!H", data[0:2])[0]
        
        # Skip header (12 bytes)
        offset = 12
        
        # Parse question section
        labels = []
        while offset < len(data):
            length = data[offset]
            if length == 0:
                offset += 1
                break
            offset += 1
            labels.append(data[offset:offset + length].decode("ascii", errors="ignore"))
            offset += length
        
        qname = ".".join(labels)
        
        # Parse QTYPE and QCLASS
        if offset + 4 > len(data):
            return None
        qtype = struct.unpack("!H", data[offset:offset + 2])[0]
        
        return qname, qtype, transaction_id
    
    def _extract_token(self, qname: str) -> str:
        """Extract canary token from DNS query name.
        
        Expected format: <token>.oob.pwnproxy.local
        """
        # Remove domain suffix
        if qname.endswith("." + self.domain):
            qname = qname[: -(len(self.domain) + 1)]
        
        # Token is the first label
        parts = qname.split(".")
        return parts[0] if parts else ""
    
    def _build_dns_response(self, transaction_id: int, qname: str) -> bytes:
        """Build a simple DNS response with a dummy A record."""
        # Header
        response = struct.pack("!H", transaction_id)  # Transaction ID
        response += struct.pack("!H", 0x8180)  # Flags: response, no error
        response += struct.pack("!H", 1)  # Questions: 1
        response += struct.pack("!H", 1)  # Answer RRs: 1
        response += struct.pack("!H", 0)  # Authority RRs: 0
        response += struct.pack("!H", 0)  # Additional RRs: 0
        
        # Question section (echo back)
        for label in qname.split("."):
            response += struct.pack("B", len(label))
            response += label.encode("ascii")
        response += b"\x00"  # End of name
        response += struct.pack("!H", 1)  # QTYPE: A
        response += struct.pack("!H", 1)  # QCLASS: IN
        
        # Answer section
        response += struct.pack("!H", 0xC00C)  # Name pointer to question
        response += struct.pack("!H", 1)  # TYPE: A
        response += struct.pack("!H", 1)  # CLASS: IN
        response += struct.pack("!I", 300)  # TTL: 300 seconds
        response += struct.pack("!H", 4)  # RDLENGTH: 4 bytes
        response += socket.inet_aton("127.0.0.1")  # RDATA: dummy IP
        
        return response
    
    @property
    def is_running(self) -> bool:
        """Check if server is running."""
        return self._running


# Global server instance
_server: Optional[DNSCallbackServer] = None


async def get_server() -> DNSCallbackServer:
    """Get the global DNS callback server instance."""
    global _server
    if _server is None:
        _server = DNSCallbackServer()
    return _server


async def start_server() -> DNSCallbackServer:
    """Start the global DNS callback server."""
    server = await get_server()
    await server.start()
    return server


async def stop_server() -> None:
    """Stop the global DNS callback server."""
    global _server
    if _server and _server.is_running:
        await _server.stop()
