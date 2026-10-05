"""TFTP server — serves the bootstrap loader (undionly.kpxe / ipxe.efi) to PXE clients.

This is the second stage of PXE boot:
1. PC gets IP via DHCP (port 67) or the router's DHCP + ProxyDHCP (port 4011)
2. DHCP tells PC to load a loader via TFTP from our server
3. PC sends TFTP RRQ → we stream the file back
4. iPXE takes over and loads the real OS via HTTP (port 8080)

TFTP is simple: client sends RRQ, we send DATA blocks, client ACKs each one.

Only the seven names in ALLOWED_BOOT_FILES are served — kernels and images go
over HTTP, which is far faster and can range-request. Apple PXE clients prefix
the request with /01-XX-XX-XX-XX-XX-XX/, which is stripped to a basename
before the allowlist check.
"""

import selectors
import socket
import struct
import threading
import time
from pathlib import Path

from src import client_journey as journey
from src import pathguard

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
    state["last_chunk"] = chunk

    return len(chunk) < TFTP_BLOCK_SIZE


def _tftp_resend_last_block(
    sock: socket.socket, addr: tuple[str, int], state: dict
) -> None:
    """Retransmit the most recent DATA block (duplicate ACK means it was lost)."""
    pkt = struct.pack("!HH", TFTP_DATA, state["block_num"]) + state.get(
        "last_chunk", b""
    )
    sock.sendto(pkt, addr)


# Anti-flood: max RRQs handled per source per second. Excess requests are
# dropped silently so a spammer can't force endless disk reads / log floods.
MAX_RRQ_PER_SECOND = 20


def _tftp_listener(port: int, boot_dir: Path, shutdown: threading.Event) -> None:
    """UDP listener for TFTP Read Requests with support for concurrent transfers."""
    sel = selectors.DefaultSelector()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", port))
    sock.setblocking(False)
    sel.register(sock, selectors.EVENT_READ)

    print(f"[*] TFTP listening on UDP {port} (root: {boot_dir})")

    # Active transfers: client_addr -> {file_data, block_num, offset, last_chunk, last_active}
    transfers: dict[tuple[str, int], dict] = {}
    TRANSFER_TIMEOUT = 30.0  # seconds
    # Sliding-window RRQ rate limiter: addr -> list of recent request timestamps
    rrq_times: dict[tuple[str, int], list[float]] = {}

    try:
        while not shutdown.is_set():
            events = sel.select(timeout=1.0)
            now = time.time()

            # Purge stale transfers and expired rate-limit windows
            stale = [
                addr
                for addr, st in transfers.items()
                if now - st["last_active"] > TRANSFER_TIMEOUT
            ]
            for addr in stale:
                del transfers[addr]
            stale_rrq = [
                addr
                for addr, times in rrq_times.items()
                if not times or now - times[-1] > 10.0
            ]
            for addr in stale_rrq:
                del rrq_times[addr]

            for _key, _mask in events:
                while True:
                    try:
                        data, addr = sock.recvfrom(2048)
                    except BlockingIOError:
                        break

                    state = transfers.get(addr)
                    if state is not None:
                        state["last_active"] = now
                        if len(data) < 4:
                            del transfers[addr]
                            continue
                        opcode = struct.unpack("!H", data[:2])[0]
                        if opcode == TFTP_ACK:
                            ack_block = struct.unpack("!H", data[2:4])[0]
                            cur = state["block_num"]
                            if ack_block == cur:
                                try:
                                    done = _tftp_send_next_block(sock, addr, state)
                                except OSError as e:
                                    # Keep the transfer state: a transient send
                                    # failure (peer vanished) should not
                                    # discard it — the client can re-ACK and we
                                    # resume from where we were.
                                    print(
                                        f"[!] TFTP: failed to send block "
                                        f"{cur} to {addr}: {e}"
                                    )
                                    continue
                                if done:
                                    del transfers[addr]
                            elif ack_block == (cur - 1) & 0xFFFF and cur > 1:
                                # Duplicate ACK — our last DATA was lost; resend it.
                                try:
                                    _tftp_resend_last_block(sock, addr, state)
                                except OSError as e:
                                    print(
                                        f"[!] TFTP: failed to resend block "
                                        f"to {addr}: {e}"
                                    )
                            # Anything else (stale/forged ACK): ignore without
                            # tearing down the transfer — timeout cleans up.
                            continue
                        if opcode != TFTP_RRQ:
                            del transfers[addr]
                            continue
                        # Fresh RRQ from an address with a stuck transfer:
                        # restart cleanly (client gave up on missing first DATA).
                        del transfers[addr]

                    filename = parse_tftp_rrq(data)
                    if not filename:
                        continue

                    # Rate-limit RRQs per source before touching disk
                    times = [t for t in rrq_times.get(addr, []) if now - t < 1.0]
                    if len(times) >= MAX_RRQ_PER_SECOND:
                        rrq_times[addr] = times
                        continue
                    times.append(now)
                    rrq_times[addr] = times

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

                    # Containment check. The allowlist already forces a bare
                    # filename, so this only has to catch symlinks (and any
                    # future caller that loosens the allowlist): bare_name can
                    # be a symlink pointing anywhere on the filesystem, and
                    # read_bytes() would happily stream the target.
                    resolved = pathguard.resolve_within(boot_dir, file_path)
                    if resolved is None:
                        print(
                            f"[!] TFTP: refusing {bare_name} from {addr} — "
                            "resolves outside the boot directory"
                        )
                        error_pkt = (
                            struct.pack("!HH", TFTP_ERROR, 2) + b"Access denied\x00"
                        )
                        sock.sendto(error_pkt, addr)
                        continue

                    if not resolved.exists():
                        print(f"[!] TFTP: {bare_name} not found at {resolved}")
                        error_pkt = (
                            struct.pack("!HH", TFTP_ERROR, 1) + b"File not found\x00"
                        )
                        sock.sendto(error_pkt, addr)
                        continue

                    try:
                        file_data = resolved.read_bytes()
                    except OSError as e:
                        print(f"[!] TFTP: failed to read {resolved.name}: {e}")
                        error_pkt = (
                            struct.pack("!HH", TFTP_ERROR, 1) + b"File not found\x00"
                        )
                        sock.sendto(error_pkt, addr)
                        continue

                    journey.record(addr[0], "TFTP", bare_name)

                    state = {
                        "file_data": file_data,
                        "block_num": 0,
                        "offset": 0,
                        "last_active": time.time(),
                    }
                    # Send failures must not escape the loop either. The
                    # journey line is recorded above, so if the DATA never
                    # went out the operator sees the TFTP stage with no HTTP
                    # stage after it and knows to look here.
                    try:
                        done = _tftp_send_next_block(sock, addr, state)
                    except OSError as e:
                        print(f"[!] TFTP: failed to send {bare_name} to {addr}: {e}")
                        continue
                    if not done:
                        transfers[addr] = state
    finally:
        sel.close()
        sock.close()
