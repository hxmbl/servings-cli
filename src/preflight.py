"""Pre-flight checks — fail loudly at startup instead of failing silently at boot time.

Historical failure mode: the banner printed, all listeners said "listening",
and no client ever booted — because the advertised server IP wasn't on any
interface, or the bootloader wasn't in the boot dir, or another DHCP server
owned the network. Every one of those is detectable before a client tries.
"""

import socket
from dataclasses import dataclass, field
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


def udp_port_free(port: int) -> bool:
    """Mirror the flags the real listener uses, so REUSEADDR behaves identically."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
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
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
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


def run_preflight(
    root_mode: bool,
    server_ip: str,
    boot_file: str,
    boot_root: Path,
    dhcp_port: int,
    tftp_port: int,
    http_port: int,
) -> PreflightResult:
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

    # Bootloader must exist AND be TFTP-allowlisted, or every client stalls.
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
    elif boot_file.encode() not in ALLOWED_BOOT_FILES:
        allowed = ", ".join(sorted(n.decode() for n in ALLOWED_BOOT_FILES))
        result.errors.append(
            f"--boot-file {boot_file!r} is not in the TFTP allowlist.\n"
            f"    DHCP will advertise it but TFTP will reject every request.\n"
            f"    Allowed: {allowed}"
        )

    port_checks = [
        ("DHCP/ProxyDHCP", dhcp_port, udp_port_free),
        ("TFTP", tftp_port, udp_port_free),
        ("HTTP", http_port, tcp_port_free),
    ]
    for service, port, check in port_checks:
        if not check(port):
            result.errors.append(
                f"{service} port {port} is already in use.\n"
                f"    Another servings-cli instance? Run 'servings-cli kill' first,\n"
                f"    or override with --port / --tftp-port / --http-port."
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
