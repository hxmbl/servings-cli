#!/usr/bin/env python3
"""DriveDroid-style USB boot workflow for Android/Termux.

Presents an ISO as USB mass storage, waits for the PC to read it,
then switches to RNDIS tethering and starts servings-cli.

Usage:
    python3 usb_boot.py                  # Interactive: pick ISO
    python3 usb_boot.py /path/to/iso.iso # Direct: use specific ISO
"""

import subprocess
import sys
import time
from pathlib import Path

DISK_IMAGE_DIRS = [
    Path("/sdcard/DiskImages"),
    Path("/storage/emulated/0/DiskImages"),
]

GADGET_BASE = "/config/usb_gadget/g1"
MASS_STORAGE = f"{GADGET_BASE}/functions/mass_storage.0"
CONFIGS = f"{GADGET_BASE}/configs/b.1"

LOG_FILE = Path(__file__).parent / "usb-switch.log"


def log(msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    with open(LOG_FILE, "a") as f:
        f.write(line + "\n")


def su(cmd: str) -> str:
    result = subprocess.run(
        ["su", "-c", cmd],
        capture_output=True,
        text=True,
        timeout=10,
    )
    return result.stdout.strip()


def find_isos() -> list[Path]:
    isos = []
    for d in DISK_IMAGE_DIRS:
        if d.exists():
            isos.extend(sorted(d.glob("*.iso")))
    return isos


def present_iso(iso_path: Path) -> None:
    log(f"Presenting {iso_path.name} as USB mass storage...")
    su(f"echo {iso_path} > {MASS_STORAGE}/lun.0/file")
    su(f"echo 1 > {MASS_STORAGE}/lun.0/removable")
    su(f"echo 1 > {MASS_STORAGE}/lun.0/ro")
    su(f"echo mass_storage,adb > {GADGET_BASE}/os_desc/use")
    su(f"echo '' > {CONFIGS}/strings/0x409/configuration/UDC")
    time.sleep(1)
    log("ISO presented — PC should see USB CD-ROM now")


def wait_for_read(timeout: int = 30) -> bool:
    log(f"Waiting up to {timeout}s for PC to read ISO...")
    stats_path = Path("/sys/class/udc/7000000.dwc3")
    start = time.time()
    while time.time() - start < timeout:
        try:
            if (stats_path / "inep_0").exists():
                log("UDC stats available — PC is reading")
        except Exception:
            pass
        time.sleep(2)
        # Simple timeout approach
        elapsed = int(time.time() - start)
        if elapsed % 10 == 0 and elapsed > 0:
            log(f"  ...{elapsed}s elapsed")
    return True


def switch_to_rndis() -> None:
    log("Switching USB gadget to RNDIS tethering...")
    su(f"echo rndis,adb > {GADGET_BASE}/os_desc/use")
    time.sleep(3)
    log("RNDIS mode activated — PC should detect USB Ethernet")


def bring_up_rndis() -> str | None:
    log("Bringing up rndis0 interface...")
    su("ip link set rndis0 up")
    time.sleep(1)

    for iface in ("rndis0", "usb0"):
        try:
            out = subprocess.check_output(
                ["ip", "-4", "-o", "addr", "show", "dev", iface],
                stderr=subprocess.DEVNULL,
                timeout=3,
            ).decode()
            for line in out.splitlines():
                if "inet " in line:
                    ip = line.strip().split()[1].split("/")[0]
                    log(f"Phone IP: {ip} ({iface})")
                    return ip
        except (subprocess.CalledProcessError, FileNotFoundError, OSError):
            continue

    # Try adding a static IP if none assigned
    su("ip addr add 192.168.42.129/24 dev rndis0")
    log("Added static IP 192.168.42.129 on rndis0")
    return "192.168.42.129"


def start_server(ip: str) -> None:
    log(f"Starting servings-cli on {ip}...")
    python = "/data/data/com.termux/files/usr/bin/python3"
    subprocess.Popen(
        [
            python,
            "-m",
            "src.main",
            "serve",
            "--no-root",
            "--android",
            "--server-ip",
            ip,
        ],
        stdout=open(LOG_FILE, "a"),
        stderr=subprocess.STDOUT,
    )
    log("servings-cli started")


def pick_iso(isos: list[Path]) -> Path | None:
    if len(isos) == 1:
        print(f"Found: {isos[0].name}")
        return isos[0]
    print("Available ISOs:")
    for i, iso in enumerate(isos):
        print(f"  [{i + 1}] {iso.name}")
    try:
        choice = int(input("Pick: ")) - 1
        return isos[choice]
    except (ValueError, IndexError):
        return None


def main() -> None:
    isos = find_isos()
    if not isos:
        print("No ISOs found in DiskImages directories.")
        sys.exit(1)

    if len(sys.argv) > 1:
        iso = Path(sys.argv[1])
        if not iso.exists():
            print(f"File not found: {iso}")
            sys.exit(1)
    else:
        iso = pick_iso(isos)
        if not iso:
            sys.exit(1)

    print(f"\n=== USB Boot: {iso.name} ===\n")
    log(f"Starting USB boot workflow with {iso.name}")

    present_iso(iso)
    wait_for_read()
    switch_to_rndis()
    ip = bring_up_rndis()
    if ip:
        start_server(ip)
    else:
        log("ERROR: Could not detect phone IP")
        sys.exit(1)

    log("Done — servings-cli is running")
    print("\nPC should now PXE boot from the phone.")
    print(f"HTTP server: http://{ip}:8080")
    print(f"Log: {LOG_FILE}")


if __name__ == "__main__":
    main()
