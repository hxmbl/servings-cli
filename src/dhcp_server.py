"""Full DHCP server — required for seamless PXE boot.

Root mode: replaces the network's DHCP server on port 67, providing
both IP assignment and PXE options (60/66/67) so clients auto-discover
the boot server.

Non-root mode is handled by proxydhcp.py on port 4011 instead.
"""

import socket
import threading
from dataclasses import dataclass, field

# DHCP message types
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5

# DHCP option tags
OPT_SUBNET_MASK = 1
OPT_ROUTER = 3
OPT_DNS = 6
OPT_DOMAIN = 15
OPT_BROADCAST = 28
OPT_VENDOR_CLASS = 60
OPT_SERVER_ID = 54
OPT_MESSAGE_TYPE = 53
OPT_TFTP_SERVER = 66
OPT_BOOT_FILE = 67
OPT_END = 255

# Magic cookie preceding DHCP options — every DHCP packet has this
MAGIC_COOKIE = b"\x63\x82\x53\x63"


@dataclass
class IPPool:
    """Simple IP pool — assigns addresses from a /24 subnet."""

    subnet: str = "192.168.42"
    next_ip: int = 100
    max_ip: int = 200
    leases: dict[str, str] = field(default_factory=dict)

    def allocate(self, mac: str) -> str:
        """Assign an IP to a MAC. Reuses existing lease if present."""
        if mac in self.leases:
            return self.leases[mac]

        ip = f"{self.subnet}.{self.next_ip}"
        self.leases[mac] = ip
        self.next_ip += 1

        if self.next_ip > self.max_ip:
            self.next_ip = 100

        return ip


def _parse_dhcp_request(data: bytes) -> dict | None:
    """Parse an incoming DHCP request (DISCOVER or REQUEST).

    Returns dict with xid, mac, msg_type, is_pxe — or None if not a valid request.
    """
    if len(data) < 240:
        return None
    if data[0] != 1:  # must be BOOTREQUEST
        return None
    if data[236:240] != MAGIC_COOKIE:
        return None

    xid = data[4:8]
    mac = data[28:34]
    mac_str = ":".join(f"{b:02x}" for b in mac)

    # Walk DHCP options to find message type and vendor class
    opts = data[240:]
    msg_type = None
    is_pxe = False
    cursor = 0

    while cursor < len(opts):
        tag = opts[cursor]
        if tag == OPT_END:
            break
        if cursor + 1 >= len(opts):
            break
        length = opts[cursor + 1]
        value = opts[cursor + 2 : cursor + 2 + length]

        if tag == OPT_MESSAGE_TYPE and length == 1:
            msg_type = value[0]
        elif tag == OPT_VENDOR_CLASS and b"PXEClient" in value:
            is_pxe = True

        cursor += 2 + length

    if msg_type not in (DHCP_DISCOVER, DHCP_REQUEST):
        return None

    return {
        "xid": xid,
        "mac": mac,
        "mac_str": mac_str,
        "msg_type": msg_type,
        "is_pxe": is_pxe,
    }


def _build_bootp_packet(
    request: dict,
    ip: str,
    server_ip: str,
    msg_type: int,
    boot_file: str,
) -> bytes:
    """Build a DHCP response packet (OFFER or ACK) with PXE options.

    Every DHCP response is a BOOTP packet with options appended.
    PXE requires options 60 (vendor class), 66 (TFTP server), and 67 (boot file).
    """
    pkt = bytearray(240)

    # BOOTP header — most fields mirror the request
    pkt[0] = 2  # op: BOOTREPLY
    pkt[1] = 1  # htype: ethernet
    pkt[2] = 6  # hlen: MAC is 6 bytes
    pkt[3] = 0  # hops
    pkt[4:8] = request["xid"]  # xid: transaction ID (client matches on this)
    pkt[16:20] = socket.inet_aton(ip)  # yiaddr: "your" IP
    pkt[20:24] = socket.inet_aton(server_ip)  # siaddr: server IP (TFTP server)
    pkt[24:28] = socket.inet_aton("0.0.0.0")  # giaddr: 0 for direct (no relay)
    pkt[28:34] = request["mac"]  # chaddr: client MAC
    pkt[236:240] = MAGIC_COOKIE

    # Build subnet for broadcast address
    parts = server_ip.split(".")
    subnet = ".".join(parts[:3])

    # DHCP options — this is where PXE magic happens
    opts = bytearray()
    opts += bytes([OPT_MESSAGE_TYPE, 1, msg_type])
    opts += bytes([OPT_SERVER_ID, 4]) + socket.inet_aton(server_ip)
    opts += bytes([OPT_SUBNET_MASK, 4]) + socket.inet_aton("255.255.255.0")
    opts += bytes([OPT_ROUTER, 4]) + socket.inet_aton(server_ip)
    opts += bytes([OPT_DNS, 4]) + socket.inet_aton(server_ip)
    opts += bytes([OPT_BROADCAST, 4]) + socket.inet_aton(f"{subnet}.255")
    opts += bytes([OPT_DOMAIN, 6]) + b"local\x00"

    # PXE-specific options — client uses these to find TFTP server + boot file
    opts += bytes([OPT_VENDOR_CLASS, 9]) + b"PXEClient"
    opts += bytes([OPT_TFTP_SERVER, 4]) + socket.inet_aton(server_ip)
    opts += bytes([OPT_BOOT_FILE, len(boot_file) + 1]) + boot_file.encode() + b"\x00"

    opts += bytes([OPT_END])

    return bytes(pkt + opts)


def dhcp_listener(
    port: int,
    boot_file: str,
    shutdown: threading.Event,
    server_ip: str = "192.168.42.129",
) -> None:
    """Full DHCP server — listens on port 67, assigns IPs, serves PXE options.

    Replaces the network's DHCP server. The PC broadcasts DHCPDISCOVER,
    we respond with an IP + PXE options, the PC then contacts our TFTP
    server to load the bootloader.

    Flow: DISCOVER → OFFER → REQUEST → ACK → PC boots via TFTP
    """
    pool = IPPool()
    parts = server_ip.split(".")
    subnet = ".".join(parts[:3])
    pool.subnet = subnet

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        s.bind(("", port))
        s.settimeout(1.0)
        print(f"[*] DHCP server listening on UDP {port} (root mode)")

        while not shutdown.is_set():
            try:
                data, addr = s.recvfrom(2048)
            except TimeoutError:
                continue

            request = _parse_dhcp_request(data)
            if not request:
                continue

            mac_str = request["mac_str"]
            is_pxe = request["is_pxe"]

            ip = pool.allocate(mac_str)
            dest = (f"{subnet}.255", 68)

            tag = "PXE" if is_pxe else "DHCP"

            if request["msg_type"] == DHCP_DISCOVER:
                print(f"[+] {tag}: DISCOVER from {mac_str} → offering {ip}")
                resp = _build_bootp_packet(
                    request, ip, server_ip, DHCP_OFFER, boot_file
                )
                s.sendto(resp, dest)
                print(f"[+] {tag}: OFFER sent {ip} to {mac_str}")

            elif request["msg_type"] == DHCP_REQUEST:
                print(f"[+] {tag}: REQUEST from {mac_str} → ACK {ip}")
                resp = _build_bootp_packet(request, ip, server_ip, DHCP_ACK, boot_file)
                s.sendto(resp, dest)
                print(f"[+] {tag}: ACK {ip} to {mac_str}")
