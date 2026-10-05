#!/usr/bin/env python3
"""DriveDroid-style USB boot workflow for Android/Termux.

Presents an ISO as USB mass storage, waits for the PC to read it,
then switches to RNDIS tethering and starts servings-cli.

Requires root (su). Every gadget write is checked, so an unrooted device or a
SELinux denial aborts with the reason logged rather than continuing to a later
step that cannot work. Progress goes to stdout and usb-switch.log.

Usage:
    python3 scripts/usb_boot.py                  # Interactive: pick ISO
    python3 scripts/usb_boot.py /path/to/iso.iso # Direct: use specific ISO
"""

import os
import shlex
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


def su(cmd: str, *, check: bool = False) -> str:
    """Run a command under su.

    Every failure mode here is silent by default: `su` missing (not rooted),
    denied, or SELinux refusing the write all produce a non-zero exit and some
    stderr. The old version discarded the return code entirely, so present_iso
    went on to log "ISO presented — PC should see USB CD-ROM now" after the
    write had in fact been refused. stderr is surfaced on failure so the log
    says why.
    """
    try:
        result = subprocess.run(
            ["su", "-c", cmd],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except FileNotFoundError:
        log(f"[!] su not found — is this device rooted? (cmd: {cmd})")
        if check:
            raise
        return ""
    except subprocess.TimeoutExpired:
        log(f"[!] su timed out after 10s: {cmd}")
        if check:
            raise
        return ""
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or "").strip()
        log(f"[!] su command failed (rc={result.returncode}): {cmd}")
        if detail:
            log(f"    {detail}")
        if check:
            raise RuntimeError(f"su failed: {cmd}: {detail}")
    return result.stdout.strip()


def find_isos() -> list[Path]:
    isos = []
    for d in DISK_IMAGE_DIRS:
        if d.exists():
            isos.extend(sorted(d.glob("*.iso")))
    return isos


def present_iso(iso_path: Path) -> None:
    """Point the USB mass-storage LUN at an ISO. Raises if a write is refused.

    Without the LUN backing file the PC sees an empty drive and every later step
    is meaningless, so these are all checked — the old version ignored su's exit
    status and logged success regardless.

    The path is shlex-quoted because it comes from shared storage, where any app
    can plant files: unquoted, a name like `pwn$(reboot).iso` would run as root
    inside the su shell.
    """
    log(f"Presenting {iso_path.name} as USB mass storage...")
    q = shlex.quote(str(iso_path))
    su(f"printf '%s\\n' {q} > {MASS_STORAGE}/lun.0/file", check=True)
    su(f"echo 1 > {MASS_STORAGE}/lun.0/removable", check=True)
    su(f"echo 1 > {MASS_STORAGE}/lun.0/ro", check=True)
    su(f"echo mass_storage,adb > {GADGET_BASE}/os_desc/use", check=True)
    su(f"echo '' > {CONFIGS}/strings/0x409/configuration/UDC", check=True)
    time.sleep(1)
    log("ISO presented — PC should see USB CD-ROM now")


def wait_for_read(timeout: int = 30) -> bool:
    """Poll UDC state until the gadget reports 'configured' (PC is reading).

    A heuristic, not proof: 'configured' means the host enumerated the device,
    not that it read the whole ISO. Returns False on timeout; the caller warns
    and continues, since a slow host is not a failure.
    """
    log(f"Waiting up to {timeout}s for PC to read ISO...")
    start = time.time()
    while time.time() - start < timeout:
        try:
            states = list(Path("/sys/class/udc").glob("*/state"))
            if any(s.read_text().strip() == "configured" for s in states):
                log("UDC configured — PC is reading")
                return True
        except OSError:
            pass
        time.sleep(2)
        elapsed = int(time.time() - start)
        if elapsed % 10 == 0 and elapsed > 0:
            log(f"  ...{elapsed}s elapsed")
    return False


def switch_to_rndis() -> None:
    log("Switching USB gadget to RNDIS tethering...")
    su(f"echo rndis,adb > {GADGET_BASE}/os_desc/use", check=True)
    time.sleep(3)
    log("RNDIS mode activated — PC should detect USB Ethernet")


def bring_up_rndis() -> str | None:
    """Return the phone's USB-tethering IPv4 address, or None if there isn't one.

    rndis0 does not always come up by itself after the mode switch (see
    DRIVEDROID-CONCEPT.md, Known Issues), so this brings it up and falls back to
    adding a static address. Returns None rather than a guessed address when
    both attempts fail: handing the server an IP it does not hold produces a
    misleading pre-flight error instead of an honest failure here.
    """
    log("Bringing up rndis0 interface...")
    su("ip link set rndis0 up", check=True)
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

    static = "192.168.42.129"
    if su(f"ip addr add {static}/24 dev rndis0", check=True):
        log(f"Added static IP {static} on rndis0")
        return static
    log(f"[!] Could not add {static}/24 to rndis0 — check USB gadget setup")
    return None


# Repository root, so the child process can import src.main regardless of
# the directory this script was launched from. `-m` resolves the module
# against the *child's* cwd, so without this the server silently failed to
# start whenever usb_boot.py was run from anywhere but the repo root.
PROJECT_ROOT = Path(__file__).resolve().parent.parent


def start_server(ip: str) -> None:
    """Launch servings-cli detached, in non-root mode, and return immediately.

    The child's own output goes to usb-switch.log, so if pre-flight rejects the
    configuration it is recorded there rather than lost — the script itself
    exits as soon as the process is spawned and cannot report that failure.
    """
    log(f"Starting servings-cli on {ip}...")
    python = "/data/data/com.termux/files/usr/bin/python3"
    if not os.path.exists(python):
        python = sys.executable
    with open(LOG_FILE, "a") as logf:
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
            cwd=str(PROJECT_ROOT),
            stdout=logf,
            stderr=subprocess.STDOUT,
        )
    log("servings-cli started (output continues in this log)")


def pick_iso(isos: list[Path]) -> Path | None:
    if len(isos) == 1:
        print(f"Found: {isos[0].name}")
        return isos[0]
    print("Available ISOs:")
    for i, iso in enumerate(isos):
        print(f"  [{i + 1}] {iso.name}")
    try:
        choice = int(input("Pick: ")) - 1
    except (ValueError, EOFError):
        print("Not a number — aborting.")
        return None
    # Both bad-input paths explain themselves; previously they exited(1) with
    # nothing printed, leaving the user to guess why nothing happened.
    if not 0 <= choice < len(isos):
        print(f"No such option (enter 1-{len(isos)}) — aborting.")
        return None
    return isos[choice]


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

    # Raises with the reason logged if any gadget write is refused.
    present_iso(iso)
    if not wait_for_read():
        log("WARNING: no confirmation the PC read the ISO — continuing anyway")
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
