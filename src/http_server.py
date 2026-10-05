"""HTTP server — streams boot payloads (kernel, initrd, ISOs) to iPXE clients."""

import os
import socket
import threading
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

from src import client_journey as journey
from src import pathguard

CHUNK_SIZE = 256 * 1024


class ReusableHTTPServer(ThreadingHTTPServer):
    """Threading HTTPServer with SO_REUSEADDR set before bind.

    Threading so one slow client (huge ISO over a slow link, or a dead socket)
    cannot block every other boot request. daemon_threads keeps shutdown
    instant even with stuck connections.
    Prevents 'Address already in use' errors after crashes.
    Skips HTTPServer.server_bind()'s socket.getfqdn() call which
    does a reverse DNS lookup that can hang for seconds on 0.0.0.0.
    """

    daemon_threads = True
    # SO_REUSEADDR means two different things depending on the platform:
    # on POSIX it says "ignore sockets left in TIME_WAIT by the previous
    # process" (exactly what a crash-and-restart needs), but on Windows it
    # means "other processes may bind this port too" — enabling it there
    # turns a restart into a silent port hijack. Only set it where it means
    # what we want.
    allow_reuse_address = os.name != "nt"
    allow_reuse_port = False

    def server_bind(self) -> None:
        if self.allow_reuse_address:
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
    # Additional directories to serve from, if a caller wants any. Nothing
    # sets this in production; it exists for embedders and tests.
    extra_paths: list[Path] = []
    # Socket timeout, applied to the whole connection. Bounds how long a dead
    # or silent client can pin a worker thread.
    timeout = 60

    def _path_allowed(self, full_path: Path) -> bool:
        """True if full_path is inside the boot root or a configured extra path.

        Compares resolved Paths, not strings: string prefix matching with a
        hard-coded "/" separator silently refused every file on Windows,
        where resolved paths use "\".
        """
        return any(
            pathguard.is_within(root, full_path)
            for root in (self.boot_root, *self.extra_paths)
        )

    def do_GET(self) -> None:
        path = unquote(self.path.lstrip("/"))
        if not path:
            self.send_error(404)
            return

        try:
            full_path = pathguard.native_join(self.boot_root, path)
        except (ValueError, OSError):
            self.send_error(404)
            return

        try:
            full_path = full_path.resolve()
        except (ValueError, OSError, RuntimeError):
            # Embedded NUL, symlink loop, unreadable parent: unusable path.
            self.send_error(404)
            return

        if not self._path_allowed(full_path):
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
            # Capture the identity now and verify it against the opened file
            # below, so a symlink swapped between check and stream cannot
            # escape the jail mid-response.
            expected = full_path.stat()
        except OSError:
            self.send_error(404)
            return

        try:
            f = open(full_path, "rb")
        except OSError as e:
            print(f"[!] HTTP: cannot open {path}: {e}")
            self.send_error(404)
            return

        with f:
            st = os.fstat(f.fileno())
            if (st.st_ino, st.st_dev) != (expected.st_ino, expected.st_dev):
                print(f"[!] HTTP: {path} changed while opening — refusing")
                self.send_error(404)
                return
            ext = full_path.suffix.lower()
            content_type = MIME_TYPES.get(ext, "application/octet-stream")
            # Recorded before the first byte goes out. Unlike DHCP and TFTP
            # there is no sendto() that can fail here — once the headers are
            # written the response is committed, and a mid-stream disconnect
            # is a client-side problem we cannot report as a failure anyway.
            journey.record(self.client_address[0], "HTTP", f"GET {path}")
            try:
                self.send_response(200)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(st.st_size))
                self.send_header("Connection", "close")
                self.end_headers()
                while True:
                    chunk = f.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
            except Exception as e:
                print(f"[!] HTTP: error serving {path}: {e}")
                traceback.print_exc()

    def log_message(self, format: str, *args: object) -> None:
        # Successful GETs are shown by the client-journey chain; only
        # surface errors here to keep the console one-line-per-event.
        code = str(args[1]) if len(args) > 1 else ""
        if code.startswith("2"):
            return
        print(f"[+] HTTP {args[0]} ({code})")


def _http_server(
    port: int, boot_root: Path, shutdown: threading.Event, bind_addr: str = "0.0.0.0"
) -> None:
    """Start the HTTP file server.

    Startup failures (e.g. the port is already taken) propagate to the
    caller's future on purpose. Swallowing them here made a dead HTTP server
    indistinguishable from a healthy one to the orchestrator: the thread
    returned, the future completed with no exception, and the crash monitor
    had nothing to report. See server._monitor_futures.
    """
    server = None
    try:
        BootHTTPHandler.boot_root = boot_root
        server = ReusableHTTPServer((bind_addr, port), BootHTTPHandler)
        print(f"[*] HTTP listening on TCP {port} (root: {boot_root})")

        def _watch_shutdown() -> None:
            shutdown.wait()
            server.shutdown()

        threading.Thread(target=_watch_shutdown, daemon=True).start()
        server.serve_forever(poll_interval=0.5)
    finally:
        if server:
            server.server_close()
