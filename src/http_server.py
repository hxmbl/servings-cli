"""HTTP server — streams boot payloads (kernel, initrd, ISOs) to iPXE clients."""

import socket
import threading
import traceback
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from urllib.parse import unquote

CHUNK_SIZE = 256 * 1024


class ReusableHTTPServer(HTTPServer):
    """HTTPServer with SO_REUSEADDR set before bind.

    Prevents 'Address already in use' errors after crashes.
    Skips HTTPServer.server_bind()'s socket.getfqdn() call which
    does a reverse DNS lookup that can hang for seconds on 0.0.0.0.
    """

    allow_reuse_address = True
    allow_reuse_port = False

    def server_bind(self) -> None:
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if self.allow_reuse_port and hasattr(socket, "SO_REUSEPORT"):
            if self.address_family in (socket.AF_INET, socket.AF_INET6):
                try:
                    self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass
        self.socket.bind(self.server_address)
        self.server_address = self.socket.getsockname()
        self.server_name = self.server_address[0]
        self.server_port = self.server_address[1]


MIME_TYPES = {
    ".kernel": "application/octet-stream",
    ".bzImage": "application/octet-stream",
    ".vmlinuz": "application/octet-stream",
    ".initrd": "application/octet-stream",
    ".img": "application/octet-stream",
    ".squashfs": "application/octet-stream",
    ".iso": "application/x-iso9660-image",
    ".kpxe": "application/octet-stream",
    ".efi": "application/octet-stream",
    ".pxe": "application/octet-stream",
    ".cfg": "text/plain",
    ".conf": "text/plain",
}


class BootHTTPHandler(BaseHTTPRequestHandler):
    """Serves boot assets from the configured boot directory."""

    boot_root: Path = Path(".")
    extra_paths: list[Path] = []

    def do_GET(self) -> None:
        path = unquote(self.path.lstrip("/"))
        if not path:
            self.send_error(404)
            return

        try:
            full_path = (self.boot_root / path).resolve()
        except (ValueError, OSError):
            self.send_error(404)
            return
        boot_root_resolved = self.boot_root.resolve()
        boot_root_str = str(boot_root_resolved)
        full_path_str = str(full_path)
        allowed = full_path_str == boot_root_str or full_path_str.startswith(
            boot_root_str + "/"
        )
        if not allowed:
            for extra in self.extra_paths:
                extra_resolved = extra.resolve()
                extra_str = str(extra_resolved)
                if full_path_str == extra_str or full_path_str.startswith(
                    extra_str + "/"
                ):
                    allowed = True
                    break
        if not allowed:
            self.send_error(403)
            return

        try:
            is_dir = full_path.is_dir()
            exists = full_path.exists()
        except OSError:
            self.send_error(404)
            return
        if not exists or is_dir:
            self.send_error(404)
            return

        try:
            file_size = full_path.stat().st_size
            ext = full_path.suffix.lower()
            content_type = MIME_TYPES.get(ext, "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(file_size))
            self.send_header("Connection", "close")
            self.end_headers()
            with open(full_path, "rb") as f:
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except Exception as e:
            print(f"[!] HTTP: error serving {path}: {e}")
            traceback.print_exc()

    def log_message(self, format: str, *args: object) -> None:
        print(f"[+] HTTP {args[0]}")


def _http_server(port: int, boot_root: Path, shutdown: threading.Event) -> None:
    """Start the HTTP file server."""
    server = None
    try:
        BootHTTPHandler.boot_root = boot_root
        server = ReusableHTTPServer(("0.0.0.0", port), BootHTTPHandler)
        print(f"[*] HTTP listening on TCP {port} (root: {boot_root})")
        server.timeout = 1.0
        while not shutdown.is_set():
            server.handle_request()
    except Exception:
        traceback.print_exc()
    finally:
        if server:
            server.server_close()
