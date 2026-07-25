"""TFTP server — serves the bootstrap loader (undionly.kpxe / ipxe.efi) to PXE clients.

This is the second stage of PXE boot:
1. PC gets IP via DHCP (port 67/4011)
2. DHCP tells PC to load "undionly.kpxe" via TFTP from our server
3. PC sends TFTP RRQ → we stream the file back
4. iPXE takes over and loads the real OS via HTTP (port 8080)

TFTP is simple: client sends RRQ, we send DATA blocks, client ACKs each one.
"""

import selectors
import socket
import struct
import threading
import time
from pathlib import Path

TFTP_RRQ = 1  # Read Request — client asks for a file
TFTP_DATA = 3  # Data block — server sends a chunk
TFTP_ACK = 4  # Acknowledgment — client confirms receipt
TFTP_ERROR = 5  # Error — something went wrong
TFTP_BLOCK_SIZE = 512  # Standard TFTP block size (bytes per packet)

ALLOWED_BOOT_FILES = frozenset(
    {
        b"undionly.kpxe",
        b"ipxe.efi",
        b"snponly.efi",
        b"snp.efi",
        b"ipxe.efi.signed",
        b"bootx64.efi",
        b"grubx64.efi",
    }
)


def parse_tftp_rrq(data: bytes) -> str | None:
    """Extract filename from a TFTP Read Request (RRQ) packet.

    RRQ format: [opcode:2][filename:N][0][mode:N][0]
    Returns the filename string, or None if malformed.
    """
    if len(data) < 4:
        return None
    opcode = struct.unpack("!H", data[:2])[0]
    if opcode != TFTP_RRQ:
        return None

    null_pos = data.find(b"\x00", 2)
    if null_pos == -1:
        return None
    return data[2:null_pos].decode("ascii", errors="replace")


def _tftp_send_next_block(
    sock: socket.socket, addr: tuple[str, int], state: dict
) -> bool:
    """Send next DATA block for an active transfer. Returns True if transfer is complete (last block)."""
    file_data = state["file_data"]
    block_num = (state["block_num"] + 1) & 0xFFFF
    offset = state["offset"]

    chunk = file_data[offset : offset + TFTP_BLOCK_SIZE]
    data_pkt = struct.pack("!HH", TFTP_DATA, block_num) + chunk
    sock.sendto(data_pkt, addr)

    state["block_num"] = block_num
    state["offset"] = offset + len(chunk)

    return len(chunk) < TFTP_BLOCK_SIZE


def _tftp_listener(port: int, boot_dir: Path, shutdown: threading.Event) -> None:
    """UDP listener for TFTP Read Requests with support for concurrent transfers."""
    sel = selectors.DefaultSelector()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", port))
    sock.setblocking(False)
    sel.register(sock, selectors.EVENT_READ)

    print(f"[*] TFTP listening on UDP {port} (root: {boot_dir})")

    # Active transfers: client_addr -> {file_data: bytes, block_num: int, offset: int, last_active: float}
    transfers: dict[tuple[str, int], dict] = {}
    TRANSFER_TIMEOUT = 30.0  # seconds

    try:
        while not shutdown.is_set():
            events = sel.select(timeout=1.0)
            now = time.time()

            # Purge stale transfers
            stale = [
                addr
                for addr, st in transfers.items()
                if now - st["last_active"] > TRANSFER_TIMEOUT
            ]
            for addr in stale:
                del transfers[addr]

            for _key, _mask in events:
                while True:
                    try:
                        data, addr = sock.recvfrom(2048)
                    except BlockingIOError:
                        break

                    if addr in transfers:
                        state = transfers[addr]
                        state["last_active"] = now
                        if len(data) < 4:
                            del transfers[addr]
                            continue
                        opcode = struct.unpack("!H", data[:2])[0]
                        if opcode != TFTP_ACK:
                            del transfers[addr]
                            continue
                        ack_block = struct.unpack("!H", data[2:4])[0]
                        if ack_block != state["block_num"]:
                            del transfers[addr]
                            continue
                        done = _tftp_send_next_block(sock, addr, state)
                        if done:
                            del transfers[addr]
                    else:
                        filename = parse_tftp_rrq(data)
                        if not filename:
                            continue

                        # Apple PXE prepends /01-XX-XX-XX-XX-XX-XX/ — strip to basename
                        bare_name = Path(filename).name
                        try:
                            bare_bytes = bare_name.encode("ascii")
                        except UnicodeEncodeError:
                            print(f"[!] TFTP: rejecting non-ASCII filename from {addr}")
                            error_pkt = (
                                struct.pack("!HH", TFTP_ERROR, 2) + b"Access denied\x00"
                            )
                            sock.sendto(error_pkt, addr)
                            continue
                        if bare_bytes not in ALLOWED_BOOT_FILES:
                            print(
                                f"[!] TFTP: rejecting unknown file '{filename}' from {addr}"
                            )
                            error_pkt = (
                                struct.pack("!HH", TFTP_ERROR, 2) + b"Access denied\x00"
                            )
                            sock.sendto(error_pkt, addr)
                            continue

                        file_path = boot_dir / bare_name
                        if not file_path.exists():
                            print(f"[!] TFTP: {bare_name} not found at {file_path}")
                            error_pkt = (
                                struct.pack("!HH", TFTP_ERROR, 1)
                                + b"File not found\x00"
                            )
                            sock.sendto(error_pkt, addr)
                            continue

                        print(
                            f"[+] TFTP: serving {bare_name} to {addr} (requested: {filename})"
                        )
                        try:
                            file_data = file_path.read_bytes()
                        except OSError as e:
                            print(f"[!] TFTP: failed to read {file_path.name}: {e}")
                            error_pkt = (
                                struct.pack("!HH", TFTP_ERROR, 1)
                                + b"File not found\x00"
                            )
                            sock.sendto(error_pkt, addr)
                            continue

                        state: dict = {
                            "file_data": file_data,
                            "block_num": 0,
                            "offset": 0,
                            "last_active": time.time(),
                        }
                        done = _tftp_send_next_block(sock, addr, state)
                        if not done:
                            transfers[addr] = state
    finally:
        sel.close()
        sock.close()
