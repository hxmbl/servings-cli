"""Shared test utilities for servings-cli test suite."""

import io
import socket
import struct
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.dhcp_server import MAGIC_COOKIE  # noqa: F401 — re-export for tests
from src.http_server import BootHTTPHandler
from src.tftp import TFTP_RRQ  # noqa: F401 — re-export for tests


def free_port() -> int:
    """Get a free TCP port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("", 0))
        return s.getsockname()[1]


def free_udp_port() -> int:
    """Get a free UDP port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def make_handler(method: str, path: str, body: bytes = b"") -> BootHTTPHandler:
    """Create a mock BootHTTPHandler for unit testing."""
    handler = BootHTTPHandler.__new__(BootHTTPHandler)
    handler.path = path
    handler.command = method
    handler.requestline = f"{method} {path} HTTP/1.1"
    handler.request_version = "HTTP/1.1"
    handler.request = MagicMock()
    handler.client_address = ("127.0.0.1", 12345)
    handler.wfile = io.BytesIO()
    handler.rfile = io.BytesIO(body)
    handler.headers = {}
    handler.close = MagicMock()
    return handler


def build_pxe_discover(
    mac: bytes = b"\x00\x11\x22\x33\x44\x55",
    arch_id: int = 0,
    xid: bytes = b"\xde\xad\xbe\xef",
) -> bytes:
    """Build a minimal PXE DISCOVER packet."""
    pkt = bytearray(240)
    pkt[0] = 1  # BOOTREQUEST
    pkt[1] = 1  # htype
    pkt[2] = 6  # hlen
    pkt[4:8] = xid
    pkt[28:34] = mac
    pkt[236:240] = MAGIC_COOKIE

    opts = bytearray()
    opts += bytes([53, 1, 1])  # DHCP DISCOVER
    arch_hex = f"{arch_id:04x}"
    vendor = f"PXEClient:Arch:{arch_hex}:UNDI:003000"
    opts += bytes([60, len(vendor)]) + vendor.encode()
    opts += bytes([255])
    return bytes(pkt + opts)


def build_non_pxe_discover(mac: bytes = b"\x00\x11\x22\x33\x44\x55") -> bytes:
    """Build a DHCP DISCOVER without PXE vendor class."""
    pkt = bytearray(240)
    pkt[0] = 1
    pkt[1] = 1
    pkt[2] = 6
    pkt[4:8] = b"\x00\x00\x00\x01"
    pkt[28:34] = mac
    pkt[236:240] = MAGIC_COOKIE

    opts = bytearray()
    opts += bytes([53, 1, 1])  # DHCP DISCOVER
    opts += bytes([60, 4]) + b"Linux"
    opts += bytes([255])
    return bytes(pkt + opts)


def build_dhcp_with_options(mac: bytes, extra_opts: bytes) -> bytes:
    """Build a DHCP DISCOVER with custom options payload."""
    pkt = bytearray(240)
    pkt[0] = 1
    pkt[1] = 1
    pkt[2] = 6
    pkt[4:8] = b"\xca\xfe\xba\xbe"
    pkt[28:34] = mac
    pkt[236:240] = MAGIC_COOKIE
    return bytes(pkt + extra_opts)


def make_rrq(filename: str) -> bytes:
    """Build a minimal TFTP Read Request packet."""
    return struct.pack("!H", TFTP_RRQ) + filename.encode() + b"\x00octet\x00"


def start_tftp(boot_dir: Path) -> tuple[int, threading.Event, threading.Thread]:
    """Start a TFTP listener on a free port and return (port, shutdown_event, thread)."""
    from src.tftp import _tftp_listener

    shutdown = threading.Event()
    port = free_udp_port()
    t = threading.Thread(target=_tftp_listener, args=(port, boot_dir, shutdown))
    t.daemon = True
    t.start()
    time.sleep(0.3)
    return port, shutdown, t


def start_http(boot_dir: Path) -> tuple[int, threading.Event, threading.Thread]:
    """Start an HTTP server on a free port and return (port, shutdown_event, thread)."""
    from src.http_server import _http_server

    shutdown = threading.Event()
    port = free_port()
    t = threading.Thread(target=_http_server, args=(port, boot_dir, shutdown))
    t.daemon = True
    t.start()
    time.sleep(0.3)
    return port, shutdown, t


def start_proxydhcp(
    server_ip: str = "127.0.0.1",
) -> tuple[int, threading.Event, threading.Thread]:
    """Start a ProxyDHCP listener on a free port and return (port, shutdown_event, thread)."""
    from src.proxydhcp import _proxydhcp_listener

    shutdown = threading.Event()
    port = free_udp_port()
    t = threading.Thread(target=_proxydhcp_listener, args=(port, shutdown, server_ip))
    t.daemon = True
    t.start()
    time.sleep(0.15)
    return port, shutdown, t
