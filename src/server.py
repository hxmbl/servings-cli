"""Thread orchestration — launches all PXE boot servers concurrently.

Root mode (default): full DHCP on 67 + TFTP on 69 (needs sudo/admin).
Non-root mode: ProxyDHCP on 4011 + TFTP on 6969 (no privileges needed).
"""

import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from src.boot_config import generate_boot_config
from src.http_server import _http_server
from src.proxydhcp import _proxydhcp_listener
from src.tftp import _tftp_listener


def _kill_previous() -> None:
    """Kill any existing servings-cli server processes to free ports."""
    if os.name == "nt":
        return
    try:
        my_pid = os.getpid()
        result = subprocess.run(
            ["pgrep", "-f", "src.main serve"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in result.stdout.strip().splitlines():
            pid = int(line.strip())
            if pid != my_pid:
                try:
                    os.kill(pid, 9)
                    print(f"[*] Killed old serve process (PID {pid})")
                except (ProcessLookupError, PermissionError):
                    pass
    except (subprocess.TimeoutExpired, FileNotFoundError, ValueError):
        pass


def _check_root() -> None:
    """Warn the user if they're trying root mode without privileges."""
    if os.name == "nt":
        return
    try:
        if os.geteuid() != 0:
            print("[!] Root mode requires root/admin privileges (bind to port 67/69).")
            print("    Run with sudo or use --no-root for non-root mode.")
            print()
    except AttributeError:
        pass


def serve(
    port: int = 4011,
    tftp_port: int = 6969,
    http_port: int = 8080,
    boot_dir: str = ".",
    root_mode: bool = True,
    server_ip: str = "192.168.42.129",
    boot_file: str = "undionly.kpxe",
    android: bool = False,
) -> None:
    _kill_previous()
    root = Path(boot_dir).resolve()
    if not root.exists():
        print(f"[!] Boot directory does not exist: {root}")
        raise SystemExit(1)

    try:
        generate_boot_config(root)
    except OSError as e:
        print(f"[!] Could not generate boot.cfg: {e}")

    if root_mode:
        _check_root()

    dhcp_port = 67 if root_mode else port
    tftp_actual = 69 if root_mode else tftp_port
    http_actual = http_port

    print()
    print("=" * 55)
    print("  servings-cli PXE Boot Server")
    print("=" * 55)
    mode_label = "ROOT" if root_mode else "non-root"
    print(f"  MODE      : {mode_label}")
    print(f"  DHCP      : UDP {dhcp_port}")
    print(f"  TFTP      : UDP {tftp_actual}")
    print(f"  HTTP      : TCP {http_actual}")
    print(f"  Boot dir  : {root}")
    print(f"  Boot file : {boot_file}")
    print(f"  Server IP : {server_ip}")
    if android:
        print("  Platform  : Android/Termux")
    print("=" * 55)
    print()

    if android and root_mode:
        print("[*] Android root mode: kill dnsmasq first:")
        print("    su -c killall dnsmasq")
        print()

    shutdown = threading.Event()
    executor = ThreadPoolExecutor(max_workers=6)

    if root_mode:
        from src.dhcp_server import dhcp_listener

        executor.submit(dhcp_listener, dhcp_port, boot_file, shutdown, server_ip)
    else:
        executor.submit(_proxydhcp_listener, dhcp_port, shutdown)

    executor.submit(_tftp_listener, tftp_actual, root, shutdown)
    executor.submit(_http_server, http_actual, root, shutdown)

    try:
        while not shutdown.is_set():
            shutdown.wait(3600)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        shutdown.set()
        executor.shutdown(wait=True)
