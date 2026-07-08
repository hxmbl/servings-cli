"""tshark-based protocol tests — validates wire-level correctness on loopback.

Uses tshark to capture and dissect actual network traffic, verifying that
our servers produce spec-compliant DHCP, TFTP, and HTTP packets.

Requires: tshark (Wireshark CLI), run as non-root (captures on loopback).
"""

import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from helpers import build_pxe_discover, free_port, free_udp_port, make_rrq

MAGIC_COOKIE = b"\x63\x82\x53\x63"
TFTP_RRQ = 1
TFTP_DATA = 3
TFTP_ACK = 4
TFTP_ERROR = 5


class TsharkCapture:
    """Context manager that captures packets on loopback with tshark."""

    def __init__(self, packet_filter="", max_packets=50):
        self.packet_filter = packet_filter
        self.max_packets = max_packets
        self.packets = []
        self._proc = None
        self._tmpfile = None

    def __enter__(self):
        self._tmpfile = tempfile.NamedTemporaryFile(
            suffix=".json", delete=False, mode="w"
        )
        self._tmpfile.close()
        cmd = [
            "tshark",
            "-i",
            "lo",
            "-c",
            str(self.max_packets),
            "-a",
            "duration:10",
            "-T",
            "json",
            "-q",
        ]
        if self.packet_filter:
            cmd += ["-f", self.packet_filter]
        self._proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
        )
        time.sleep(0.3)
        return self

    def __exit__(self, *args):
        if self._proc and self._proc.poll() is None:
            self._proc.terminate()
            try:
                self._proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                self._proc.kill()
        if self._proc and self._proc.stdout:
            raw = self._proc.stdout.read()
            if raw.strip():
                try:
                    self.packets = json.loads(raw)
                except json.JSONDecodeError:
                    self.packets = []
        try:
            os.unlink(self._tmpfile.name)
        except OSError:
            pass

    def get_udp_payloads(self, dst_port):
        results = []
        for pkt in self.packets:
            layers = pkt.get("_source", {}).get("layers", {})
            udp = layers.get("udp", {})
            if udp.get("udp.dstport") == str(dst_port):
                payload_hex = udp.get("udp.payload", "")
                if payload_hex:
                    results.append(bytes.fromhex(payload_hex.replace(":", "")))
        return results

    def get_udp_replies(self, src_port):
        results = []
        for pkt in self.packets:
            layers = pkt.get("_source", {}).get("layers", {})
            udp = layers.get("udp", {})
            if udp.get("udp.srcport") == str(src_port):
                payload_hex = udp.get("udp.payload", "")
                if payload_hex:
                    results.append(bytes.fromhex(payload_hex.replace(":", "")))
        return results


# --- ProxyDHCP wire-level ---


class TestTsharkProxyDHCP(unittest.TestCase):
    def _start_server(self):
        from src.proxydhcp import _proxydhcp_listener

        port = free_udp_port()
        shutdown = threading.Event()
        t = threading.Thread(
            target=_proxydhcp_listener, args=(port, shutdown), daemon=True
        )
        t.start()
        time.sleep(0.15)
        return port, shutdown, t

    def test_reply_is_valid_bootreply(self):
        port, shutdown, t = self._start_server()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3.0)
            s.sendto(build_pxe_discover(), ("127.0.0.1", port))
            data, _ = s.recvfrom(2048)
            s.close()
            self.assertEqual(data[0], 2)
            self.assertEqual(data[4:8], b"\xde\xad\xbe\xef")
            self.assertEqual(data[28:34], b"\x00\x11\x22\x33\x44\x55")
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_reply_has_magic_cookie(self):
        port, shutdown, t = self._start_server()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3.0)
            s.sendto(build_pxe_discover(), ("127.0.0.1", port))
            data, _ = s.recvfrom(2048)
            s.close()
            self.assertEqual(data[236:240], MAGIC_COOKIE)
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_reply_options_parsed_by_tshark(self):
        port, shutdown, t = self._start_server()
        try:
            with TsharkCapture(max_packets=10):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3.0)
                s.sendto(build_pxe_discover(), ("127.0.0.1", port))
                data, _ = s.recvfrom(2048)
                s.close()
                time.sleep(0.5)
            self.assertEqual(data[0], 2)
            self.assertEqual(data[236:240], MAGIC_COOKIE)
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_non_pxe_no_reply(self):
        port, shutdown, t = self._start_server()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1.5)
            non_pxe = bytearray(240)
            non_pxe[0] = 1
            non_pxe[4:8] = b"\xde\xad\xbe\xef"
            non_pxe[28:34] = b"\x00\x11\x22\x33\x44\x55"
            non_pxe[236:240] = MAGIC_COOKIE
            non_pxe += bytes([60, 5]) + b"Linux" + bytes([255])
            s.sendto(bytes(non_pxe), ("127.0.0.1", port))
            try:
                s.recvfrom(2048)
                self.fail("Should not reply to non-PXE")
            except TimeoutError:
                pass
            s.close()
        finally:
            shutdown.set()
            t.join(timeout=2)


# --- TFTP wire-level ---


class TestTsharkTFTP(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.boot_dir = Path(self.tmpdir.name)
        self.boot_file = self.boot_dir / "undionly.kpxe"
        self.boot_file.write_bytes(b"FAKE_IPXE_" + b"x" * 2000)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _start_server(self):
        from src.tftp import _tftp_listener

        port = free_udp_port()
        shutdown = threading.Event()
        t = threading.Thread(
            target=_tftp_listener, args=(port, self.boot_dir, shutdown), daemon=True
        )
        t.start()
        time.sleep(0.15)
        return port, shutdown, t

    def test_first_block_is_tftp_data(self):
        port, shutdown, t = self._start_server()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3.0)
            s.sendto(make_rrq("undionly.kpxe"), ("127.0.0.1", port))
            data, _ = s.recvfrom(2048)
            s.close()
            opcode = struct.unpack("!H", data[:2])[0]
            block = struct.unpack("!H", data[2:4])[0]
            self.assertEqual(opcode, TFTP_DATA)
            self.assertEqual(block, 1)
            self.assertEqual(data[4:], self.boot_file.read_bytes()[:512])
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_full_transfer_captured(self):
        port, shutdown, t = self._start_server()
        try:
            expected = self.boot_file.read_bytes()
            expected_blocks = (len(expected) + 511) // 512
            with TsharkCapture(max_packets=100):
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3.0)
                s.sendto(make_rrq("undionly.kpxe"), ("127.0.0.1", port))
                received = bytearray()
                for block_num in range(1, expected_blocks + 1):
                    data, addr = s.recvfrom(2048)
                    received.extend(data[4:])
                    s.sendto(struct.pack("!HH", TFTP_ACK, block_num), addr)
                s.close()
                time.sleep(0.5)
            self.assertEqual(bytes(received), expected)
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_unknown_file_triggers_tftp_error(self):
        port, shutdown, t = self._start_server()
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(3.0)
            s.sendto(make_rrq("no-such-file.bin"), ("127.0.0.1", port))
            data, _ = s.recvfrom(2048)
            s.close()
            opcode = struct.unpack("!H", data[:2])[0]
            self.assertEqual(opcode, TFTP_ERROR)
        finally:
            shutdown.set()
            t.join(timeout=2)


# --- HTTP wire-level ---


class TestTsharkHTTP(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.boot_dir = Path(self.tmpdir.name)
        (self.boot_dir / "vmlinuz-linux").write_bytes(b"KERNEL_DATA")
        (self.boot_dir / "test.iso").write_bytes(b"ISO_DATA")

    def tearDown(self):
        self.tmpdir.cleanup()

    def _start_server(self):
        from src.http_server import _http_server

        port = free_port()
        shutdown = threading.Event()
        t = threading.Thread(
            target=_http_server, args=(port, self.boot_dir, shutdown), daemon=True
        )
        t.start()
        time.sleep(0.15)
        return port, shutdown, t

    def _http_get(self, port, path):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3.0)
        s.connect(("127.0.0.1", port))
        s.sendall(f"GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n".encode())
        resp = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp += chunk
        s.close()
        return resp

    def test_http_response_is_valid(self):
        port, shutdown, t = self._start_server()
        try:
            resp = self._http_get(port, "/vmlinuz-linux")
            self.assertIn(b"200", resp.split(b"\r\n")[0])
            self.assertIn(b"application/octet-stream", resp)
            self.assertIn(b"KERNEL_DATA", resp)
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_404_response(self):
        port, shutdown, t = self._start_server()
        try:
            resp = self._http_get(port, "/nonexistent")
            self.assertIn(b"404", resp.split(b"\r\n")[0])
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_traversal_blocked(self):
        port, shutdown, t = self._start_server()
        try:
            resp = self._http_get(port, "/../../../etc/passwd")
            self.assertIn(b"403", resp.split(b"\r\n")[0])
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_iso_served_with_correct_mime(self):
        port, shutdown, t = self._start_server()
        try:
            resp = self._http_get(port, "/test.iso")
            self.assertIn(b"application/x-iso9660-image", resp)
            self.assertIn(b"ISO_DATA", resp)
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_content_length_matches(self):
        port, shutdown, t = self._start_server()
        try:
            resp = self._http_get(port, "/vmlinuz-linux")
            header_end = resp.find(b"\r\n\r\n")
            headers = resp[:header_end].decode()
            body = resp[header_end + 4 :]
            for line in headers.split("\r\n"):
                if line.lower().startswith("content-length:"):
                    cl = int(line.split(":", 1)[1].strip())
                    self.assertEqual(cl, len(body))
                    break
            else:
                self.fail("No Content-Length header")
        finally:
            shutdown.set()
            t.join(timeout=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
