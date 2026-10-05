"""Thread orchestration — launches all PXE boot servers concurrently.

Root mode (default): full DHCP on 67 + TFTP on 69 (needs sudo/admin).
Non-root mode: ProxyDHCP on 4011 + TFTP on 6969 (no privileges needed).
HTTP always listens on 8080 (or --http-port).

Startup order matters and is deliberate: config pre-flight first, so a bad
setting cannot kill a working instance; then boot.cfg generation; then the
takeover of any existing instance; then the port checks, which are only
meaningful once that instance is gone.
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
from src.preflight import PreflightResult, run_preflight
from src.proxydhcp import BIOS_LOADER, PROXY_BOOT_FILES, _proxydhcp_listener
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


def _kill_previous() -> bool:
    """Kill any existing servings-cli server processes to free ports.

    Candidates from pgrep are verified against their full command line before
    being signalled — both to avoid killing unrelated processes and to guard
    against killing a recycled PID.

    Returns True if at least one process was signalled. A False return on a
    platform without pgrep is a real limitation, not a success, so callers
    can tell the user instead of leaving them to discover it as a port clash.
    """
    if os.name == "nt":
        print(
            "[!] Cannot detect existing servers on Windows — "
            "process discovery is not implemented there."
        )
        print("    If startup reports a port clash, stop the other instance manually.")
        return False
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
            return False
        ps = subprocess.run(
            ["ps", "-o", "pid=,command=", "-p", ",".join(pids)],
            capture_output=True,
            text=True,
            timeout=5,
        )
        killed = False
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
                killed = True
                print(f"[*] Killed old serve process (PID {pid})")
            except (ProcessLookupError, PermissionError):
                pass
        return killed
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        print(f"[!] Could not check for existing servers: {e}")
        return False


def _check_privileges() -> None:
    """Warn if root mode is being attempted without the rights to bind 67/69.

    Root mode is a warning, not an error: the pre-flight port check catches
    the bind failure anyway and this only saves the user from a confusing
    "port already in use" message.
    """
    if os.name == "nt":
        # Windows has no geteuid; being an Administrator is what matters.
        try:
            import ctypes

            if not ctypes.windll.shell32.IsUserAnAdmin():
                print("[!] Root mode requires an Administrator shell (to bind 67/69).")
                print("    Reopen PowerShell/cmd as Administrator, or use --no-root.")
                print()
        except (AttributeError, OSError):
            pass
        return
    try:
        if os.geteuid() != 0:
            print("[!] Root mode requires root/admin privileges (bind to port 67/69).")
            print("    Run with sudo or use --no-root for non-root mode.")
            print()
    except AttributeError:
        pass


def _monitor_futures(
    futures: dict, shutdown: threading.Event, on_death: "callable | None" = None
) -> None:
    """Watch the server futures and report each one that dies.

    Reports each failure exactly once. The previous version re-printed the
    same traceback every five seconds for as long as the process lived,
    which buried the original error under a wall of repeats and left the
    process happily serving the protocols that had *not* crashed — the
    console said everything was fine.

    ``on_death`` (if given) is invoked with the (name, exception) of the
    first failure so the caller can shut the whole thing down.
    """
    reported: set[str] = set()
    while not shutdown.is_set():
        shutdown.wait(5)
        for name, future in futures.items():
            if name in reported:
                continue
            if not future.done():
                continue
            exc = future.exception()
            if exc is None:
                # Clean return (e.g. shutdown) — not a crash.
                continue
            reported.add(name)
            print(f"[!] {name} server CRASHED: {exc}")
            traceback.print_exception(type(exc), exc, exc.__traceback__)
            if on_death is not None:
                on_death(name, exc)


def serve(
    port: int = 4011,
    tftp_port: int = 6969,
    http_port: int = 8080,
    boot_dir: str = ".",
    root_mode: bool = True,
    server_ip: str = "192.168.42.129",
    boot_file: str = "undionly.kpxe",
    android: bool = False,
    force: bool = False,
) -> None:
    root = Path(boot_dir).resolve()
    if not root.exists():
        print(f"[!] Boot directory does not exist: {root}")
        raise SystemExit(1)

    dhcp_port = 67 if root_mode else port
    tftp_actual = 69 if root_mode else tftp_port
    http_actual = http_port

    # Which bootloaders must be present? Root mode advertises exactly
    # --boot-file. ProxyDHCP ignores it and picks per client architecture, so
    # the BIOS loader is required and the EFI one is merely recommended —
    # checking --boot-file there validated a file nothing would ever request.
    if root_mode:
        required_boot_files = [boot_file]
        optional_boot_files: list[str] = []
    else:
        required_boot_files = [BIOS_LOADER]
        optional_boot_files = [name for name in PROXY_BOOT_FILES if name != BIOS_LOADER]

    def _run_preflight(check_ports: bool) -> PreflightResult:
        return run_preflight(
            root_mode=root_mode,
            server_ip=server_ip,
            boot_file=boot_file,
            boot_root=root,
            dhcp_port=dhcp_port,
            tftp_port=tftp_actual,
            http_port=http_actual,
            boot_files=required_boot_files,
            optional_boot_files=optional_boot_files,
            check_ports=check_ports,
        )

    def _report(result: PreflightResult) -> None:
        for warning in result.warnings:
            print(f"[!] {warning}")
            print()
        if not result.errors:
            return
        if force:
            print("[!] --force: ignoring pre-flight errors above")
            print()
            return
        for error in result.errors:
            print(f"[x] {error}")
            print()
        print("    Start anyway with --force")
        raise SystemExit(1)

    # Pass 1: config only, before taking the ports over, so a typo'd
    # --server-ip can't take down a server that is currently working.
    pf = _run_preflight(check_ports=False)
    _report(pf)

    # Write boot.cfg before the takeover: every client fetches it over HTTP, so
    # an unwritable boot dir means a 404 menu and nothing boots. An OSError
    # here is fatal (unless --force) for the same reason.
    try:
        generate_boot_config(root)
    except OSError as e:
        pf.errors.append(
            f"could not write boot.cfg to {root}: {e}\n"
            "    Every client fetches /boot.cfg over HTTP after TFTP, so the\n"
            "    boot menu would 404 and nothing would boot.\n"
            "    Check that the boot directory exists and is writable."
        )
        _report(pf)

    _kill_previous()

    # Pass 2: port availability is only a fair question once the previous
    # instance has let go of them.
    _report(_run_preflight(check_ports=True))

    if root_mode:
        _check_privileges()

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
    if root_mode:
        print(f"  Boot file : {boot_file}")
    else:
        print(
            f"  Boot files: {', '.join(required_boot_files)}"
            + (
                f" (+{', '.join(optional_boot_files)} for UEFI clients)"
                if optional_boot_files
                else ""
            )
        )
    print(f"  Server IP : {server_ip}")
    print(f"  Client URL: http://{server_ip}:{http_actual}/boot.cfg")
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

    # A dead listener means the server cannot do its job. Say so once and
    # stop, rather than staying alive serving a partial PXE chain and leaving
    # the user to work out why clients stall.
    def _on_server_death(name: str, exc: BaseException) -> None:
        print(f"[!] {name} server died — shutting down.")
        shutdown.set()

    monitor = threading.Thread(
        target=_monitor_futures,
        args=(futures, shutdown, _on_server_death),
        daemon=True,
    )
    monitor.start()

    exit_code = 0
    try:
        # Sleep in slices rather than once for an hour, so a listener failure
        # noticed by the monitor takes effect promptly.
        while not shutdown.is_set():
            shutdown.wait(3600)
        # Distinguish "a listener crashed" from "the user pressed Ctrl-C":
        # exit non-zero on the former so a supervising script can tell.
        for future in futures.values():
            if future.done() and not future.cancelled() and future.exception():
                exit_code = 1
    except KeyboardInterrupt:
        print("\n[*] Shutting down...")
    finally:
        shutdown.set()
        executor.shutdown(wait=True)

    if exit_code:
        raise SystemExit(1)
