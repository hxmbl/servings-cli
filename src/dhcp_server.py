"""Full DHCP server — required for seamless PXE boot.

Root mode: replaces the network's DHCP server on port 67, providing
both IP assignment and PXE options (60/66/67) so clients auto-discover
the boot server.

Every DISCOVER and REQUEST is answered, PXE or not, with the PXE options
included. Replies go to the subnet broadcast on port 68, since the client may
not have an address yet.

Addresses come from IPPool, which is fixed-size and has no lease expiry —
see that class for why.

Non-root mode is handled by proxydhcp.py on port 4011 instead.
"""

import socket
import threading
from collections.abc import Callable
from dataclasses import dataclass, field

from src import client_journey as journey

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
    """Simple IP pool — assigns addresses from a /24 subnet.

    No lease expiry: leases last until the process exits. This is a PXE server
    for temporary sessions, so that is the right trade — a client that walks
    away just leaves an entry behind, and the pool is only ever recycled after
    ~101 distinct clients in one run.

    Wraps around when exhausted, evicting the holder of the address it reuses.
    Note what that means: eviction is *not* a way of avoiding address
    conflicts, it is the moment one is created. The evicted client still holds
    that address and is never told. Every eviction is therefore logged —
    silently recycling an address is how you get two machines that both
    believe they own it, with no hint in the console as to why.
    """

    subnet: str = "192.168.42"
    next_ip: int = 100
    max_ip: int = 200
    leases: dict[str, str] = field(default_factory=dict)
    ip_owner: dict[str, str] = field(default_factory=dict)
    #: Called with (ip, evicted_mac, new_mac) whenever the pool must recycle an
    #: address that is still recorded as leased. Used by the listener to warn.
    on_evict: "Callable[[str, str, str], None] | None" = None

    def allocate(self, mac: str) -> str:
        """Assign an IP to a MAC. Reuses existing lease if present."""
        if mac in self.leases:
            return self.leases[mac]

        ip = f"{self.subnet}.{self.next_ip}"
        if ip in self.ip_owner:
            # Pool wrapped around onto an address another client still holds.
            # Evict so we never hand the same address to two recorded leases,
            # but say out loud that we did it: the previous holder is not told.
            victim = self.ip_owner.pop(ip)
            del self.leases[victim]
            if self.on_evict is not None:
                self.on_evict(ip, victim, mac)

        self.leases[mac] = ip
        self.ip_owner[ip] = mac
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
        if tag == 0:  # PAD — single byte, no length field (RFC 2132 §23.1)
            cursor += 1
            continue
        if cursor + 2 > len(opts):
            break
        length = opts[cursor + 1]
        if cursor + 2 + length > len(opts):
            break
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
    boot_file_bytes = boot_file.encode() + b"\x00"
    if len(boot_file_bytes) > 255:
        raise ValueError(
            f"boot file name too long for DHCP option 67 "
            f"({len(boot_file_bytes)} bytes, max 254)"
        )
    opts += bytes([OPT_BOOT_FILE, len(boot_file_bytes)]) + boot_file_bytes

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
    broadcast = f"{subnet}.255"

    def _warn_eviction(ip: str, victim: str, new_mac: str) -> None:
        print(
            f"[!] DHCP: address pool exhausted — recycling {ip} from "
            f"{victim} to {new_mac}.\n"
            f"    {victim} may still be using this address."
        )

    pool.on_evict = _warn_eviction

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
            dest = (broadcast, 68)
            journey.link_ip_to_mac(ip, mac_str)

            tag = "PXE" if is_pxe else "DHCP"

            if request["msg_type"] == DHCP_DISCOVER:
                print(f"[+] {tag}: DISCOVER from {mac_str}")
                resp = _build_bootp_packet(
                    request, ip, server_ip, DHCP_OFFER, boot_file
                )
                detail = f"OFFER {ip}"
            elif request["msg_type"] == DHCP_REQUEST:
                resp = _build_bootp_packet(request, ip, server_ip, DHCP_ACK, boot_file)
                detail = f"ACK {ip}"
            else:
                continue

            try:
                s.sendto(resp, dest)
            except OSError as e:
                # A reply that cannot be sent (route withdrawn, interface down,
                # broadcast refused) must not take down the listener: the
                # exception used to escape the thread and kill DHCP entirely,
                # so one unreachable client stopped the whole boot chain.
                # Report it and keep serving.
                print(f"[!] DHCP: failed to send {detail} to {mac_str}: {e}")
                continue
            journey.record(mac_str, "DHCP", detail)
