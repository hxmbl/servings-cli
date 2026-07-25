"""servings-cli — Portable PXE/Boot server.

Root mode is the default (full DHCP on port 67, TFTP on port 69).
Use --no-root for ProxyDHCP on port 4011 (works alongside your existing DHCP).
Use --android for Termux/Android-specific paths and IP auto-detection.
"""

import sys
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import typer  # noqa: E402

from src.server import _kill_previous  # noqa: E402
from src.server import serve as _serve  # noqa: E402

app = typer.Typer()

_BOOT_DIR_CANDIDATES = [
    Path.home() / "servings-boot",
    Path.home() / "tftp",
    Path("/srv/tftp"),
    Path("/var/lib/tftpboot"),
]

_ANDROID_BOOT_DIR_CANDIDATES = [
    Path("/sdcard/DiskImages"),
    Path("/storage/emulated/0/DiskImages"),
]

_VENTOY_MARKERS = frozenset({"ventoy", "Ventoy", "VENTOY"})
_ISO_EXTENSIONS = frozenset({".iso", ".img"})


def _detect_usb_boot_dirs() -> list[Path]:
    """Scan mounted removable drives for ISOs and boot files.

    Looks for drives that contain .iso files or Ventoy marker files.
    Checks /mnt/*, /media/*, /run/media/* mount points.
    """
    candidates: list[Path] = []
    mount_roots = [Path("/mnt"), Path("/media"), Path("/run/media")]

    for mount_root in mount_roots:
        if not mount_root.exists():
            continue
        for entry in mount_root.iterdir():
            try:
                if not entry.is_dir():
                    continue
            except PermissionError:
                continue
            # Skip system dirs
            if entry.name in ("preseed", "cdrom", "floppy"):
                continue
            try:
                has_isos = any(
                    f.suffix.lower() in _ISO_EXTENSIONS
                    for f in entry.iterdir()
                    if f.is_file() and not f.name.startswith(".")
                )
                has_ventoy = any(
                    f.name in _VENTOY_MARKERS or f.name.lower() == "ventoy"
                    for f in entry.iterdir()
                )
                if has_isos or has_ventoy:
                    candidates.append(entry)
            except PermissionError:
                continue

    return candidates


def _detect_usb_ip() -> str | None:
    """Detect IP address on a USB tethering interface."""
    import subprocess

    for iface in ("usb0", "rndis0", "enx*"):
        try:
            out = subprocess.check_output(
                ["ip", "-4", "-o", "addr", "show", "dev", iface],
                stderr=subprocess.DEVNULL,
                timeout=3,
            ).decode()
            for line in out.splitlines():
                line = line.strip()
                if "inet " in line:
                    return line.split()[1].split("/")[0]
        except (subprocess.CalledProcessError, FileNotFoundError, OSError):
            continue

    # Fallback: check lsblk for USB devices
    try:
        out = subprocess.check_output(
            ["lsblk", "-rno", "NAME,TYPE,MOUNTPOINT"],
            stderr=subprocess.DEVNULL,
            timeout=3,
        ).decode()
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[1] == "part" and parts[2] != "":
                try:
                    vendor = (
                        Path(f"/sys/block/{parts[0]}/device/vendor").read_text().strip()
                    )
                    if "USB" in vendor.upper():
                        mount = Path(parts[2])
                        if mount.exists():
                            return str(mount)
                except (FileNotFoundError, PermissionError):
                    pass
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass

    return None


def _resolve_boot_dir(explicit: str | None, android: bool = False) -> str:
    if explicit:
        return explicit
    candidates = list(_BOOT_DIR_CANDIDATES)
    if android:
        candidates.extend(_ANDROID_BOOT_DIR_CANDIDATES)
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    # Auto-detect mounted USB drives with ISOs
    usb_dirs = _detect_usb_boot_dirs()
    if usb_dirs:
        # Prefer the one with the most ISOs
        best = max(
            usb_dirs,
            key=lambda d: sum(
                1
                for f in d.iterdir()
                if f.is_file() and f.suffix.lower() in _ISO_EXTENSIONS
            ),
        )
        print(f"[*] Auto-detected USB drive: {best}")
        return str(best)
    return "."


def _detect_android_ip() -> str | None:
    import subprocess

    for iface in ("rndis0", "usb0", "eth0"):
        try:
            out = subprocess.check_output(
                ["ip", "-4", "addr", "show", iface],
                stderr=subprocess.DEVNULL,
                timeout=3,
            ).decode()
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    return line.split()[1].split("/")[0]
        except (subprocess.CalledProcessError, FileNotFoundError, OSError):
            continue
    return None


@app.command()
def kill() -> None:
    """Kill any running servings-cli server processes."""
    _kill_previous()


@app.command()
def serve(
    port: int = typer.Option(
        4011, help="DHCP/ProxyDHCP UDP port (only used with --no-root)"
    ),
    tftp_port: int = typer.Option(
        6969, help="TFTP UDP port (only used with --no-root)"
    ),
    http_port: int = typer.Option(8080, help="HTTP TCP port for iPXE payloads"),
    boot_dir: str = typer.Option(
        None, help="Directory containing boot files (default: auto-detect)"
    ),
    no_root: bool = typer.Option(
        False, "--no-root", help="Non-root mode: ProxyDHCP on 4011 + TFTP on 6969"
    ),
    server_ip: str = typer.Option(
        None, help="Server IP on the client network (default: 192.168.42.129)"
    ),
    boot_file: str = typer.Option("undionly.kpxe", help="Boot file to serve"),
    android: bool = typer.Option(
        False,
        "--android",
        help="Android/Termux mode: scan shared storage, auto-detect USB IP",
    ),
) -> None:
    """Start PXE boot servers.

    Root mode (default): full DHCP on port 67 + TFTP on port 69.
    Requires sudo/root on your machine.

    Non-root mode: ProxyDHCP on 4011 + TFTP on 6969.
    Works alongside your existing DHCP server.

    --android: Termux-specific paths + USB IP auto-detection.

    Examples:
      sudo servings-cli serve
      sudo servings-cli serve --server-ip 192.168.1.100
      servings-cli serve --no-root
      servings-cli serve --android
    """
    if not server_ip:
        if android:
            detected = _detect_android_ip()
            if detected:
                server_ip = detected
                print(f"[*] Auto-detected Android USB tethering IP: {server_ip}")
            else:
                server_ip = "192.168.42.129"
        else:
            server_ip = "192.168.42.129"

    resolved = _resolve_boot_dir(boot_dir, android=android)
    _serve(
        port=port,
        tftp_port=tftp_port,
        http_port=http_port,
        boot_dir=resolved,
        root_mode=not no_root,
        server_ip=server_ip,
        boot_file=boot_file,
        android=android,
    )


def entry_point() -> None:
    app()


if __name__ == "__main__":
    entry_point()
