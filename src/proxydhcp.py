"""ProxyDHCP server — answers PXE clients with a boot file, nothing more.

Non-root mode (port 4011, --port): runs alongside an existing DHCP server
(e.g. your router). The router assigns the address; this server only adds the
PXE options, so it sends no yiaddr and no subnet/router options.

It answers *any* BOOTREQUEST carrying option 60 (PXEClient) regardless of
message type, and always replies with DHCPACK. Clients accept that in the
proxy flow.

The loader is chosen from the client's architecture (see _detect_boot_file)
rather than from --boot-file, which root mode uses instead.

Root mode (port 67): replaces the existing DHCP server entirely — see
dhcp_server.py.
"""

import socket
import threading

from src import client_journey as journey


def parse_packet(data: bytes, addr: tuple[str, int]) -> dict[str, object] | None:
    """Parse a DHCP/BOOTP packet and return PXE client info if valid.

    Returns a dict with client_address, transaction_id, mac_raw, mac_readable,
    boot_file (undionly.kpxe for BIOS, ipxe.efi for EFI).
    Returns None if the packet isn't a valid PXE request.
    """
    if len(data) < 240:
        return None

    if data[0] != 1:  # BOOTREQUEST — client → server
        return None

    transaction_id = data[4:8]
    client_mac = data[28:34]
    mac_readable = ":".join(f"{b:02x}" for b in client_mac)

    # DHCP magic cookie marks the start of the options field
    if data[236:240] != b"\x63\x82\x53\x63":
        return None

    # Walk options looking for vendor class (option 60) containing "PXEClient"
    options_bytes = data[240:]
    cursor = 0
    vendor_class = b""

    while cursor < len(options_bytes):
        tag = options_bytes[cursor]
        if tag == 255:  # end marker
            break
        if tag == 0:  # PAD — single byte, no length field (RFC 2132 §23.1)
            cursor += 1
            continue
        if cursor + 2 > len(options_bytes):
            break
        length = options_bytes[cursor + 1]
        if cursor + 2 + length > len(options_bytes):
            break
        value = options_bytes[cursor + 2 : cursor + 2 + length]

        if tag == 60:
            vendor_class = value
            if b"PXEClient" in value:
                break

        cursor += 2 + length

    if b"PXEClient" not in vendor_class:
        return None

    # Detect BIOS vs EFI from vendor class string: "PXEClient:Arch:XXXX:..."
    # Arch 0 = BIOS, 6/7/8/9 = EFI variants
    boot_file = _detect_boot_file(vendor_class)
    return {
        "client_address": addr,
        "transaction_id": transaction_id,
        "mac_raw": client_mac,
        "mac_readable": mac_readable,
        "boot_file": boot_file,
    }


#: Boot loaders this server can advertise. Kept next to the detection logic
#: so pre-flight can validate exactly the set that will be served instead of
#: guessing.
BIOS_LOADER = "undionly.kpxe"
EFI_LOADER = "ipxe.efi"
PROXY_BOOT_FILES = (BIOS_LOADER, EFI_LOADER)


def _subnet_broadcast(server_ip: str) -> str:
    """Broadcast address for server_ip's /24 — matches the root-mode DHCP path."""
    return ".".join(server_ip.split(".")[:3]) + ".255"


def _detect_boot_file(vendor_class: bytes) -> str:
    """Choose the right iPXE bootloader based on PXE client architecture.

    The vendor class string contains "PXEClient:Arch:XXXX:..." where XXXX is
    the architecture ID. 0x0000 = BIOS (undionly.kpxe), 6-9 = EFI (ipxe.efi).
    """
    try:
        decoded = vendor_class.decode("ascii", errors="replace")
        if "Arch:" in decoded:
            arch_str = decoded.split("Arch:")[1].split(":")[0].split(",")[0].strip()
            arch_id = int(arch_str, 16)
            if arch_id == 0:
                return "undionly.kpxe"
            else:
                return "ipxe.efi"
    except (ValueError, IndexError):
        pass
    # Default: BIOS (safest fallback — undionly.kpxe chainloads iPXE for EFI too)
    return "undionly.kpxe"


def send_proxy_reply(
    sock: socket.socket, client_info: dict[str, object], server_ip: str
) -> None:
    """Build and send a ProxyDHCP reply with boot file info.

    Only sends the PXE options (54, 60, 66, 67) — the IP was already assigned
    by Android's DHCP server. This is ProxyDHCP, not full DHCP.
    """
    packet = bytearray(240)

    # BOOTP header
    packet[0] = 2  # BOOTREPLY
    packet[1] = 1  # htype: ethernet
    packet[2] = 6  # hlen: MAC length
    packet[3] = 0  # hops

    packet[4:8] = client_info["transaction_id"]
    packet[28:34] = client_info["mac_raw"]

    # DHCP magic cookie — required before options
    packet[236:240] = b"\x63\x82\x53\x63"

    # DHCP options — what the PXE client needs to find the boot file
    packet += b"\x35\x01\x05"  # option 53: DHCPACK
    packet += b"\x36\x04" + socket.inet_aton(server_ip)  # option 54: server identifier
    packet += b"\x3c\x09PXEClient"  # option 60: vendor class (marks this as PXE)
    packet += b"\x42\x04" + socket.inet_aton(server_ip)  # option 66: TFTP server IP
    boot_file = (client_info["boot_file"] + "\x00").encode()
    packet += b"\x43" + bytes([len(boot_file)]) + boot_file  # option 67: boot file name
    packet += b"\xff"  # end marker

    # Where to send the reply.
    #
    # Normally unicast back to the source: a client that already has an address
    # (mid-RENEW, or a ROM that sends the proxy request late) gets a targeted
    # reply. But a client with no address yet sends from 0.0.0.0, as RFC 2131
    # specifies, and sendto(("0.0.0.0", 68)) is routed to *this* host's
    # loopback — the reply would be delivered to ourselves and the client would
    # never see it. Use the subnet broadcast in that case, which is what the
    # full DHCP server does unconditionally.
    src_ip, src_port = (
        client_info["client_address"][0],
        client_info["client_address"][1],
    )
    if src_ip in ("0.0.0.0", "::"):
        dst_ip = _subnet_broadcast(server_ip)
        dst_port = 68
    else:
        dst_ip = src_ip
        dst_port = src_port or 68

    target_address = (dst_ip, dst_port)
    sock.sendto(packet, target_address)
    journey.record(
        dst_ip,
        "PXE",
        f"{client_info['boot_file']} ({client_info['mac_readable']})",
    )


def _proxydhcp_listener(
    port: int, shutdown: threading.Event, server_ip: str = "192.168.42.129"
) -> None:
    """UDP listener for ProxyDHCP requests on non-root (port 4011).

    Works alongside an existing DHCP server. The ProxyDHCP only adds PXE
    options after the client gets an IP from the network's DHCP.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(("", port))
        s.settimeout(1.0)
        print(f"[*] ProxyDHCP listening on UDP {port}")

        while not shutdown.is_set():
            try:
                data, addr = s.recvfrom(2048)
            except TimeoutError:
                continue
            client_info = parse_packet(data, addr)
            if not client_info:
                continue
            try:
                send_proxy_reply(s, client_info, server_ip)
            except OSError as e:
                # Same reasoning as the full DHCP listener: a reply that cannot
                # be delivered must not kill the listener. Report and continue.
                print(f"[!] ProxyDHCP: failed to reply to {addr}: {e}")
