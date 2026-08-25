"""Thread orchestration — launches all PXE boot servers concurrently.

Root mode (default): full DHCP on 67 + TFTP on 69 (needs sudo/admin).
Non-root mode: ProxyDHCP on 4011 + TFTP on 6969 (no privileges needed).
"""

import os
import re
import subprocess
import threading
import traceback
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from src.boot_config import generate_boot_config
from src.http_server import _http_server
from src.proxydhcp import _proxydhcp_listener
from src.tftp import _tftp_listener


def _is_serve_cmdline(cmdline: str) -> bool:
    """True only for real servings-cli server invocations.

    Requires a python/launcher first token AND `serve` as its own token right
    after the module/script token. `pgrep -f` alone would also match unrelated
    processes whose command line merely contains the string, e.g.
    `vim src/main serve_notes.md` or `grep -r src.main serve docs`.
    """
    tokens = cmdline.split()
    if len(tokens) < 2:
        return False
    # Case-insensitive + .exe-tolerant: macOS ps reports the resolved
    # framework binary (".../MacOS/Python"), Windows uses "Python.exe".
    first_base = re.sub(r".*[\\/]", "", tokens[0]).lower()
    if first_base.endswith(".exe"):
        first_base = first_base[: -len(".exe")]
    looks_like_launcher = (
        first_base.startswith(("python", "pypy")) or "servings-cli" in first_base
    )
    if not looks_like_launcher:
        return False
    for i in range(1, len(tokens) - 1):
        prev_tok = tokens[i - 1]
        tok_base = re.sub(r".*[\\/]", "", tokens[i]).lower()
        module_form = prev_tok == "-m" and tok_base == "src.main"
        script_form = tok_base == "main.py" or "servings-cli" in tok_base
        if (module_form or script_form) and tokens[i + 1] == "serve":
            return True
    return False


def _kill_previous() -> None:
    """Kill any existing servings-cli server processes to free ports.

    Candidates from pgrep are verified against their full command line before
    being signalled — both to avoid killing unrelated processes and to guard
    against killing a recycled PID.
    """
    if os.name == "nt":
        return
    try:
        my_pid = os.getpid()
        result = subprocess.run(
            ["pgrep", "-f", r"src\.main serve|servings-cli serve"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        pids = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if not pids:
            return
        ps = subprocess.run(
            ["ps", "-o", "pid=,command=", "-p", ",".join(pids)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        for line in ps.stdout.splitlines():
            parts = line.strip().split(None, 1)
            if len(parts) != 2:
                continue
            try:
                pid = int(parts[0])
            except ValueError:
                continue
            if pid == my_pid:
                continue
            if not _is_serve_cmdline(parts[1]):
                continue
            try:
                os.kill(pid, 9)
                print(f"[*] Killed old serve process (PID {pid})")
            except (ProcessLookupError, PermissionError):
                pass
    except (subprocess.TimeoutExpired, FileNotFoundError):
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


def _monitor_futures(futures: dict, shutdown: threading.Event) -> None:
    """Periodically check server futures for unexpected deaths."""
    while not shutdown.is_set():
        shutdown.wait(5)
        for name, future in futures.items():
            if future.done():
                exc = future.exception()
                if exc is not None:
                    print(f"[!] {name} server CRASHED: {exc}")
                    traceback.print_exception(type(exc), exc, exc.__traceback__)


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

    futures: dict = {}

    if root_mode:
        from src.dhcp_server import dhcp_listener

        futures["DHCP"] = executor.submit(
            dhcp_listener, dhcp_port, boot_file, shutdown, server_ip
        )
    else:
        futures["ProxyDHCP"] = executor.submit(
            _proxydhcp_listener, dhcp_port, shutdown, server_ip
        )

    futures["TFTP"] = executor.submit(_tftp_listener, tftp_actual, root, shutdown)
    futures["HTTP"] = executor.submit(_http_server, http_actual, root, shutdown)

    monitor = threading.Thread(
        target=_monitor_futures, args=(futures, shutdown), daemon=True
    )
    monitor.start()

    try:
        while not shutdown.is_set():
            shutdown.wait(3600)
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
        shutdown.set()
        executor.shutdown(wait=True)
