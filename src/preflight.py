"""Pre-flight checks — fail loudly at startup instead of failing silently at boot time.

Historical failure mode: the banner printed, all listeners said "listening",
and no client ever booted — because the advertised server IP wasn't on any
interface, or the bootloader wasn't in the boot dir, or another DHCP server
owned the network. Every one of those is detectable before a client tries.

Split by whether the answer depends on the ports being free:

* ``check_ports=False`` — config only. Run before taking over from a running
  instance, which still owns the ports.
* ``check_ports=True`` — the above plus port availability. Run after the kill.

Bootloaders come in two flavours: ``boot_files`` must be present and
allowlisted, while ``optional_boot_files`` are only advertised to some clients
(a missing ipxe.efi breaks UEFI clients only, so it is a warning).
"""

import os
import socket
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

from src.tftp import ALLOWED_BOOT_FILES

IPXE_BOOT_URL = "https://boot.ipxe.org"


@dataclass
class PreflightResult:
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


def ip_is_local(ip: str) -> bool:
    """True if the address is assigned to a local interface."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.bind((ip, 0))
            return True
        except OSError:
            return False


def local_interface_ips() -> list[str]:
    """Best-effort list of non-loopback local IPv4 addresses (for error hints)."""
    hints: set[str] = set()
    try:
        infos = socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)
        hints |= {info[4][0] for info in infos}
    except OSError:
        pass
    try:
        # connect() on a UDP socket sends nothing; it just picks an iface
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            hints.add(s.getsockname()[0])
    except OSError:
        pass
    local = sorted(h for h in hints if not h.startswith("127."))
    return local


def udp_port_free(port: int, reuse_port: bool = False) -> bool:
    """Report whether a UDP listener could bind ``port``.

    Mirrors the flags the real listener uses. ``reuse_port`` must match the
    listener: SO_REUSEPORT lets several sockets share a port on Linux, so
    probing with it when the listener does not use it reports "free" for a
    port the listener would then fail to bind.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if reuse_port and hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        try:
            s.bind(("", port))
            return True
        except OSError:
            return False


def tcp_port_free(port: int) -> bool:
    """Report whether a TCP listener could bind ``port``.

    Mirrors ReusableHTTPServer: SO_REUSEADDR is only set on POSIX, because on
    Windows it means "others may bind this too" and would make a genuinely
    busy port look free.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        if os.name != "nt":
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("", port))
            return True
        except OSError:
            return False


def probe_existing_dhcp(timeout: float = 1.5) -> str | None:
    """Broadcast a DHCPDISCOVER; describe any DHCP server that answers.

    Best effort — returns None on any socket limitation (no broadcast perms,
    offline interfaces), so it can never block startup.
    """
    pkt = bytearray(240)
    pkt[0] = 1  # BOOTREQUEST
    pkt[4:8] = b"\x73\x65\x72\x76"  # xid "serv"
    pkt[236:240] = b"\x63\x82\x53\x63"
    opts = bytes([53, 1, 1]) + bytes([255])  # DHCPDISCOVER + end
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        sock.sendto(bytes(pkt) + opts, ("255.255.255.255", 67))
        data, addr = sock.recvfrom(2048)
        if len(data) >= 240 and data[0] == 2:  # BOOTREPLY
            responder = addr[0]
            server_id = _extract_server_id(data)
            detail = (
                f"server-id {server_id}" if server_id else f"responded from {responder}"
            )
            return f"{detail}"
    except (OSError, TimeoutError):
        pass
    finally:
        if sock:
            sock.close()
    return None


def _extract_server_id(reply: bytes) -> str | None:
    opts = reply[240:]
    cursor = 0
    while cursor < len(opts):
        tag = opts[cursor]
        if tag == 255:
            break
        if tag == 0:
            cursor += 1
            continue
        if cursor + 2 > len(opts):
            break
        length = opts[cursor + 1]
        if cursor + 2 + length > len(opts):
            break
        if tag == 54 and length == 4:
            return socket.inet_ntoa(opts[cursor + 2 : cursor + 6])
        cursor += 2 + length
    return None


def _check_boot_file(
    boot_root: Path, boot_file: str, result: PreflightResult
) -> bool:
    """Report on one advertised bootloader. True if present and allowlisted."""
    boot_path = boot_root / boot_file
    if not boot_path.exists():
        fetch = (
            f"curl -o {boot_path} {IPXE_BOOT_URL}/{boot_file}"
            if boot_file.encode() in ALLOWED_BOOT_FILES
            else "place a bootloader there (see README)"
        )
        result.errors.append(
            f"boot file missing: {boot_path}\n"
            f"    PXE clients will stall requesting it via TFTP.\n"
            f"    Fetch it: {fetch}\n"
            f"    Or pass --boot-file with a file you've placed in {boot_root}"
        )
        return False
    if boot_file.encode() not in ALLOWED_BOOT_FILES:
        allowed = ", ".join(sorted(n.decode() for n in ALLOWED_BOOT_FILES))
        result.errors.append(
            f"--boot-file {boot_file!r} is not in the TFTP allowlist.\n"
            f"    DHCP will advertise it but TFTP will reject every request.\n"
            f"    Allowed: {allowed}"
        )
        return False
    return True


def run_preflight(
    root_mode: bool,
    server_ip: str,
    boot_file: str,
    boot_root: Path,
    dhcp_port: int,
    tftp_port: int,
    http_port: int,
    boot_files: list[str] | None = None,
    optional_boot_files: list[str] | None = None,
    check_ports: bool = True,
) -> PreflightResult:
    """Validate a startup configuration.

    ``boot_files`` is the set of bootloaders that MUST be present and
    allowlisted. Defaults to ``[boot_file]``, which is exactly what root mode
    advertises.

    ``optional_boot_files`` is the set this mode *may* advertise depending on
    the client — non-root ProxyDHCP picks undionly.kpxe or ipxe.efi from the
    PXE vendor class and ignores ``--boot_file`` entirely. Their absence is a
    warning: some client classes will stall, but the config is still valid.

    ``check_ports=False`` runs only the checks that don't depend on the ports
    being free. Used for the pass that runs *before* taking over from a
    running instance — that instance still owns the ports, so probing them
    then would report conflicts that are about to disappear.
    """
    result = PreflightResult()

    # The advertised IP must exist here — clients TFTP/HTTP to it directly,
    # and it's handed out as router+DNS in root mode.
    if not ip_is_local(server_ip):
        hints = ", ".join(local_interface_ips())
        result.errors.append(
            f"server-ip {server_ip} is NOT assigned to any local interface.\n"
            f"    Clients will be told to fetch boot files from {server_ip} and never connect.\n"
            f"    Local IPs: {hints}\n"
            f"    Fix: pass --server-ip <one of the above>"
        )

    # Required bootloaders must exist AND be TFTP-allowlisted, or clients stall.
    # The caller passes the set this mode actually advertises, which is why
    # --boot_file alone is not enough: in non-root mode ProxyDHCP chooses
    # undionly.kpxe or ipxe.efi per client from the vendor class and never
    # consults --boot_file, so checking it would either demand a file nobody
    # would request or pass while the file that *would* be requested was absent.
    for candidate in boot_files or [boot_file]:
        _check_boot_file(boot_root, candidate, result)

    # Conditionally-needed loaders. Missing one is not fatal — a BIOS-only or
    # EFI-only network is a perfectly valid setup — but those specific clients
    # will stall, so warn rather than fail.
    for candidate in optional_boot_files or []:
        if (boot_root / candidate).exists():
            continue
        result.warnings.append(
            f"{candidate} is not in {boot_root}.\n"
            "    Clients needing it will stall at TFTP.\n"
            f"    Fetch it: curl -o {boot_root / candidate} "
            f"{IPXE_BOOT_URL}/{candidate}"
        )

    if not check_ports:
        return result

    # Each probe must use the same socket options as the listener it stands in
    # for, or it answers a different question than "will this bind?".
    # The full DHCP listener sets SO_REUSEPORT; ProxyDHCP and TFTP do not.
    port_checks = [
        ("DHCP/ProxyDHCP", dhcp_port, partial(udp_port_free, reuse_port=root_mode)),
        ("TFTP", tftp_port, udp_port_free),
        ("HTTP", http_port, tcp_port_free),
    ]
    for service, port, check in port_checks:
        if not check(port):
            hint = (
                "    Another servings-cli instance? Run 'servings-cli kill' first,\n"
                "    or override with --port / --tftp-port / --http-port."
            )
            if os.name == "nt":
                # kill is a no-op on Windows, so do not send the user down a
                # dead end; tell them what to do instead.
                hint = (
                    "    Another servings-cli instance may be running. On Windows\n"
                    "    'servings-cli kill' is unsupported — stop it manually, or\n"
                    "    override with --port / --tftp-port / --http-port."
                )
            result.errors.append(
                f"{service} port {port} is already in use.\n" + hint
            )

    if root_mode:
        responder = probe_existing_dhcp()
        if responder:
            result.warnings.append(
                f"existing DHCP server detected ({responder}).\n"
                f"    Root mode replaces it — devices may lose connectivity until we stop.\n"
                f"    Use --no-root alongside an existing DHCP instead."
            )

    return result
