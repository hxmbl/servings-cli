"""Integration tests — real sockets, real servers, no mocks."""

import os
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from helpers import (
    build_pxe_discover,
    make_rrq,
    start_http,
    start_proxydhcp,
    start_tftp,
)

from src.tftp import TFTP_ACK, TFTP_DATA, TFTP_ERROR

# --- ProxyDHCP ---


class TestProxyDHCPIntegration(unittest.TestCase):
    def test_responds_to_pxe_discover(self):
        port, shutdown, t = start_proxydhcp()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(build_pxe_discover(), ("127.0.0.1", port))
            data, _ = sock.recvfrom(2048)
            self.assertGreater(len(data), 240)
            self.assertEqual(data[0], 2)
            self.assertEqual(data[4:8], b"\xde\xad\xbe\xef")
            self.assertEqual(data[28:34], b"\x00\x11\x22\x33\x44\x55")
            self.assertEqual(data[236:240], b"\x63\x82\x53\x63")
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_reply_contains_pxe_options(self):
        port, shutdown, t = start_proxydhcp()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(build_pxe_discover(), ("127.0.0.1", port))
            data, _ = sock.recvfrom(2048)
            opts = data[240:]
            self.assertIn(b"PXEClient", opts)
            self.assertIn(b"undionly.kpxe", opts)
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_non_pxe_request_ignored(self):
        port, shutdown, t = start_proxydhcp()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(1.5)
            non_pxe = bytearray(240)
            non_pxe[0] = 1
            non_pxe[4:8] = b"\xde\xad\xbe\xef"
            non_pxe[28:34] = b"\x00\x11\x22\x33\x44\x55"
            non_pxe[236:240] = b"\x63\x82\x53\x63"
            non_pxe += bytes([60, 5]) + b"Linux" + bytes([255])
            sock.sendto(bytes(non_pxe), ("127.0.0.1", port))
            try:
                sock.recvfrom(2048)
                self.fail("Should not respond to non-PXE")
            except TimeoutError:
                pass
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_efi_client_gets_ipxe_efi(self):
        port, shutdown, t = start_proxydhcp()
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(build_pxe_discover(arch_id=7), ("127.0.0.1", port))
            data, _ = sock.recvfrom(2048)
            self.assertIn(b"ipxe.efi", data)
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_multiple_clients(self):
        port, shutdown, t = start_proxydhcp()
        socks = []
        try:
            for mac, xid in [
                (b"\x00\x11\x22\x33\x44\x55", b"\x01\x00\x00\x01"),
                (b"\xaa\xbb\xcc\xdd\xee\xff", b"\x02\x00\x00\x02"),
                (b"\x11\x22\x33\x44\x55\x66", b"\x03\x00\x00\x03"),
            ]:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(3.0)
                s.bind(("", 0))
                pkt = bytearray(240)
                pkt[0] = 1
                pkt[1] = 1
                pkt[2] = 6
                pkt[4:8] = xid
                pkt[28:34] = mac
                pkt[236:240] = b"\x63\x82\x53\x63"
                pkt += bytes([60, 9]) + b"PXEClient" + bytes([255])
                s.sendto(bytes(pkt), ("127.0.0.1", port))
                socks.append((s, xid, mac))
            for s, xid, mac in socks:
                data, _ = s.recvfrom(2048)
                self.assertEqual(data[0], 2)
                self.assertEqual(data[4:8], xid)
                self.assertEqual(data[28:34], mac)
        finally:
            shutdown.set()
            for s, _, _ in socks:
                s.close()
            t.join(timeout=2)


# --- TFTP ---


class TestTFTPIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.boot_dir = Path(self.tmpdir.name)
        self.boot_file = self.boot_dir / "undionly.kpxe"
        self.boot_file.write_bytes(b"FAKE_IPXE_" + b"x" * 2000)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_serves_first_block(self):
        port, shutdown, t = start_tftp(self.boot_dir)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(make_rrq("undionly.kpxe"), ("127.0.0.1", port))
            data, _ = sock.recvfrom(2048)
            opcode, block = struct.unpack("!HH", data[:4])
            self.assertEqual(opcode, TFTP_DATA)
            self.assertEqual(block, 1)
            self.assertEqual(data[4:], self.boot_file.read_bytes()[:512])
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_serves_full_file_multi_block(self):
        port, shutdown, t = start_tftp(self.boot_dir)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(make_rrq("undionly.kpxe"), ("127.0.0.1", port))
            expected = self.boot_file.read_bytes()
            expected_blocks = (len(expected) + 511) // 512
            received = bytearray()
            for block_num in range(1, expected_blocks + 1):
                data, addr = sock.recvfrom(2048)
                received.extend(data[4:])
                sock.sendto(struct.pack("!HH", TFTP_ACK, block_num), addr)
            self.assertEqual(bytes(received), expected)
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_rejects_unknown_file(self):
        port, shutdown, t = start_tftp(self.boot_dir)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(make_rrq("unknown.bin"), ("127.0.0.1", port))
            data, _ = sock.recvfrom(2048)
            self.assertEqual(struct.unpack("!H", data[:2])[0], TFTP_ERROR)
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_rejects_allowed_but_missing_file(self):
        port, shutdown, t = start_tftp(self.boot_dir)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(make_rrq("ipxe.efi"), ("127.0.0.1", port))
            data, _ = sock.recvfrom(2048)
            self.assertEqual(struct.unpack("!H", data[:2])[0], TFTP_ERROR)
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_apple_mac_path_prefix_stripped(self):
        port, shutdown, t = start_tftp(self.boot_dir)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            rrq = make_rrq("/01-aa-bb-cc-dd-ee-ff/undionly.kpxe")
            sock.sendto(rrq, ("127.0.0.1", port))
            data, _ = sock.recvfrom(2048)
            self.assertEqual(struct.unpack("!H", data[:2])[0], TFTP_DATA)
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_last_block_is_short(self):
        port, shutdown, t = start_tftp(self.boot_dir)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(make_rrq("undionly.kpxe"), ("127.0.0.1", port))
            expected = self.boot_file.read_bytes()
            expected_blocks = (len(expected) + 511) // 512
            last_data = b""
            for block_num in range(1, expected_blocks + 1):
                data, addr = sock.recvfrom(2048)
                last_data = data[4:]
                sock.sendto(struct.pack("!HH", TFTP_ACK, block_num), addr)
            self.assertLess(len(last_data), 512)
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_concurrent_transfers(self):
        """Different ports create independent transfer state."""
        port, shutdown, t = start_tftp(self.boot_dir)
        try:
            rrq = make_rrq("undionly.kpxe")
            c1 = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            c1.settimeout(3)
            c1.sendto(rrq, ("127.0.0.1", port))
            d1, _ = c1.recvfrom(2048)
            self.assertEqual(struct.unpack("!H", d1[:2])[0], TFTP_DATA)
            c1.close()
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_symlink_to_outside_returns_error(self):
        """Symlink pointing outside boot_dir — TFTP returns ERROR.

        Regression: the listener used to read through the symlink with no
        containment check at all, so the target's bytes were streamed to any
        client on the LAN. read_bytes() happily follows symlinks.

        setUp already created undionly.kpxe as a real file, so it must be
        removed before symlinking — otherwise symlink_to raises FileExistsError,
        which is an OSError, and the test skips itself instead of testing
        anything. That is exactly how it managed to skip silently for so long.
        """
        outside = Path(tempfile.mkdtemp()) / "secret.txt"
        outside.write_bytes(b"SECRET")
        link = self.boot_dir / "undionly.kpxe"
        link.unlink(missing_ok=True)
        try:
            link.symlink_to(outside)
        except OSError as e:
            self.skipTest(f"Cannot create symlinks: {e}")
            return
        # Prove the symlink is really in place — a silent skip must not be
        # mistaken for a passing containment check.
        self.assertTrue(link.is_symlink(), "symlink was not created")
        port, shutdown, t = start_tftp(self.boot_dir)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(make_rrq("undionly.kpxe"), ("127.0.0.1", port))
            data, _ = sock.recvfrom(2048)
            self.assertEqual(struct.unpack("!H", data[:2])[0], TFTP_ERROR)
            self.assertNotIn(b"SECRET", data)
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)
            outside.unlink(missing_ok=True)
            link.unlink(missing_ok=True)

    def test_symlink_to_dir_returns_error(self):
        """Symlink to a directory returns ERROR."""
        subdir = self.boot_dir / "subdir"
        subdir.mkdir()
        link = self.boot_dir / "undionly.kpxe"
        link.unlink(missing_ok=True)
        try:
            link.symlink_to(subdir)
        except OSError as e:
            self.skipTest(f"Cannot create symlinks: {e}")
            return
        self.assertTrue(link.is_symlink(), "symlink was not created")
        port, shutdown, t = start_tftp(self.boot_dir)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(make_rrq("undionly.kpxe"), ("127.0.0.1", port))
            data, _ = sock.recvfrom(2048)
            self.assertEqual(struct.unpack("!H", data[:2])[0], TFTP_ERROR)
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_unreadable_file_returns_error(self):
        """chmod 000 on allowed file returns TFTP ERROR."""
        allowed = self.boot_dir / "undionly.kpxe"
        allowed.write_bytes(b"\x00" * 100)
        os.chmod(allowed, 0o000)
        port, shutdown, t = start_tftp(self.boot_dir)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(make_rrq("undionly.kpxe"), ("127.0.0.1", port))
            data, _ = sock.recvfrom(2048)
            self.assertEqual(struct.unpack("!H", data[:2])[0], TFTP_ERROR)
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)
            os.chmod(allowed, 0o644)

    def test_bad_ack_does_not_kill_transfer(self):
        """A stale/forged ACK is ignored — the transfer survives and advances on a valid ACK."""
        port, shutdown, t = start_tftp(self.boot_dir)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(make_rrq("undionly.kpxe"), ("127.0.0.1", port))
            data, _ = sock.recvfrom(2048)
            self.assertEqual(struct.unpack("!H", data[:2])[0], TFTP_DATA)
            # Forged/stale ACK (block 99) must NOT tear down the transfer
            sock.sendto(struct.pack("!HH", TFTP_ACK, 99), ("127.0.0.1", port))
            try:
                sock.settimeout(0.5)
                sock.recvfrom(2048)
                self.fail("Bad ACK should not trigger any response")
            except TimeoutError:
                pass
            sock.settimeout(3.0)
            # Valid ACK still works — transfer state survived
            sock.sendto(struct.pack("!HH", TFTP_ACK, 1), ("127.0.0.1", port))
            data2, _ = sock.recvfrom(2048)
            opcode, block = struct.unpack("!HH", data2[:4])
            self.assertEqual(opcode, TFTP_DATA)
            self.assertEqual(block, 2)
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_duplicate_ack_resends_last_block(self):
        """Duplicate ACK of the last block means our DATA was lost — server resends it."""
        port, shutdown, t = start_tftp(self.boot_dir)
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(3.0)
            sock.sendto(make_rrq("undionly.kpxe"), ("127.0.0.1", port))
            d1, _ = sock.recvfrom(2048)
            self.assertEqual(struct.unpack("!HH", d1[:4]), (TFTP_DATA, 1))
            sock.sendto(struct.pack("!HH", TFTP_ACK, 1), ("127.0.0.1", port))
            d2, _ = sock.recvfrom(2048)
            self.assertEqual(struct.unpack("!HH", d2[:4]), (TFTP_DATA, 2))
            # Duplicate ACK for block 1 — resend block 2 verbatim
            sock.sendto(struct.pack("!HH", TFTP_ACK, 1), ("127.0.0.1", port))
            d2_again, _ = sock.recvfrom(2048)
            self.assertEqual(d2_again, d2)
            sock.close()
        finally:
            shutdown.set()
            t.join(timeout=2)


# --- HTTP ---


class TestHTTPIntegration(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.boot_dir = Path(self.tmpdir.name)
        self.kernel_file = self.boot_dir / "vmlinuz-linux"
        self.kernel_file.write_bytes(b"KERNEL_" + b"x" * 10000)
        self.iso_file = self.boot_dir / "ubuntu.iso"
        self.iso_file.write_bytes(b"ISO_" + b"y" * 5000)

    def tearDown(self):
        self.tmpdir.cleanup()

    def _get(self, path):
        import urllib.request

        req = urllib.request.Request(f"http://127.0.0.1:{self.port}{path}")
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, dict(resp.headers), resp.read()

    def test_serves_kernel_with_correct_type(self):
        self.port, shutdown, t = start_http(self.boot_dir)
        try:
            status, headers, body = self._get("/vmlinuz-linux")
            self.assertEqual(status, 200)
            self.assertEqual(body, self.kernel_file.read_bytes())
            self.assertEqual(headers.get("Content-Type"), "application/octet-stream")
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_serves_iso_with_correct_type(self):
        self.port, shutdown, t = start_http(self.boot_dir)
        try:
            status, headers, body = self._get("/ubuntu.iso")
            self.assertEqual(status, 200)
            self.assertEqual(body, self.iso_file.read_bytes())
            self.assertEqual(headers.get("Content-Type"), "application/x-iso9660-image")
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_content_length_matches_file(self):
        self.port, shutdown, t = start_http(self.boot_dir)
        try:
            status, headers, body = self._get("/vmlinuz-linux")
            self.assertEqual(status, 200)
            self.assertEqual(
                int(headers.get("Content-Length", "0")), self.kernel_file.stat().st_size
            )
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_404_for_missing_file(self):
        self.port, shutdown, t = start_http(self.boot_dir)
        try:
            import urllib.error

            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self._get("/nonexistent.iso")
            self.assertEqual(ctx.exception.code, 404)
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_403_for_traversal(self):
        self.port, shutdown, t = start_http(self.boot_dir)
        try:
            import urllib.error

            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self._get("/../../../etc/passwd")
            self.assertEqual(ctx.exception.code, 403)
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_subdirectory_file_is_served(self):
        """Regression: files below the boot root must be reachable.

        The jail used to compare resolved strings against a hard-coded '/'
        separator, so on Windows it refused every file in the tree. This
        pins the behaviour the generated boot.cfg depends on.
        """
        sub = self.boot_dir / "distros" / "arch"
        sub.mkdir(parents=True)
        (sub / "arch.iso").write_bytes(b"NESTED_ISO")
        self.port, shutdown, t = start_http(self.boot_dir)
        try:
            status, _, body = self._get("/distros/arch/arch.iso")
            self.assertEqual(status, 200)
            self.assertEqual(body, b"NESTED_ISO")
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_symlinked_file_outside_boot_dir_refused(self):
        outside = Path(tempfile.mkdtemp()) / "secret.txt"
        outside.write_bytes(b"SECRET")
        link = self.boot_dir / "leak.iso"
        try:
            link.symlink_to(outside)
        except OSError as e:
            self.skipTest(f"Cannot create symlinks: {e}")
        self.assertTrue(link.is_symlink(), "symlink was not created")
        self.port, shutdown, t = start_http(self.boot_dir)
        try:
            import urllib.error

            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self._get("/leak.iso")
            self.assertEqual(ctx.exception.code, 403)
        finally:
            shutdown.set()
            t.join(timeout=2)
            outside.unlink(missing_ok=True)
            link.unlink(missing_ok=True)

    def test_404_for_root_path(self):
        self.port, shutdown, t = start_http(self.boot_dir)
        try:
            import urllib.error

            with self.assertRaises(urllib.error.HTTPError) as ctx:
                self._get("/")
            self.assertEqual(ctx.exception.code, 404)
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_large_file_streaming(self):
        large_file = self.boot_dir / "large.iso"
        large_file.write_bytes(b"LARGE_" + b"a" * 300 * 1024)
        self.port, shutdown, t = start_http(self.boot_dir)
        try:
            status, _, body = self._get("/large.iso")
            self.assertEqual(status, 200)
            self.assertEqual(body, large_file.read_bytes())
        finally:
            shutdown.set()
            t.join(timeout=2)

    def test_extra_path_served(self):
        from src.http_server import BootHTTPHandler

        extra_dir = Path(self.tmpdir.name) / "extra"
        extra_dir.mkdir()
        (extra_dir / "test.efi").write_bytes(b"EXTRA_EFI")
        BootHTTPHandler.extra_paths = [extra_dir]
        self.port, shutdown, t = start_http(self.boot_dir)
        try:
            status, _, body = self._get("/extra/test.efi")
            self.assertEqual(status, 200)
            self.assertEqual(body, b"EXTRA_EFI")
        finally:
            BootHTTPHandler.extra_paths = []
            shutdown.set()
            t.join(timeout=2)


if __name__ == "__main__":
    unittest.main(verbosity=2)
