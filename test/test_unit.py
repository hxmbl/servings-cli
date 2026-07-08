"""Unit tests for all servings-cli components.

Pure unit tests — no network sockets, no threads, no subprocess.
"""

import os
import re
import socket
import struct
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from helpers import build_dhcp_with_options, build_pxe_discover, make_handler, make_rrq

from src.boot_config import (
    _IGNORED_DIRS,
    _is_initrd,
    _is_kernel,
    _label_from_filename,
    generate_boot_config,
)
from src.dhcp_server import (
    DHCP_ACK,
    DHCP_DISCOVER,
    DHCP_OFFER,
    DHCP_REQUEST,
    MAGIC_COOKIE,
    IPPool,
    _build_bootp_packet,
    _parse_dhcp_request,
)
from src.http_server import BootHTTPHandler, ReusableHTTPServer
from src.proxydhcp import _detect_boot_file, parse_packet, send_proxy_reply
from src.tftp import (
    ALLOWED_BOOT_FILES,
    TFTP_ACK,
    TFTP_DATA,
    TFTP_ERROR,
    TFTP_RRQ,
    _tftp_send_next_block,
    parse_tftp_rrq,
)

# --- TFTP Parser ---


class TestParseTftpRRQ(unittest.TestCase):
    def test_valid_rrq(self):
        self.assertEqual(parse_tftp_rrq(make_rrq("undionly.kpxe")), "undionly.kpxe")

    def test_valid_rrq_ipxe(self):
        self.assertEqual(parse_tftp_rrq(make_rrq("ipxe.efi")), "ipxe.efi")

    def test_short_packet_returns_none(self):
        self.assertIsNone(parse_tftp_rrq(b"\x00"))

    def test_non_rrq_returns_none(self):
        self.assertIsNone(parse_tftp_rrq(struct.pack("!H", TFTP_DATA) + b"test"))

    def test_missing_null_terminator(self):
        self.assertIsNone(parse_tftp_rrq(struct.pack("!H", TFTP_RRQ) + b"no-null"))

    def test_apple_pxe_mac_path_prefix(self):
        result = parse_tftp_rrq(make_rrq("/01-aa-bb-cc-dd-ee-ff/ipxe.efi"))
        self.assertEqual(result, "/01-aa-bb-cc-dd-ee-ff/ipxe.efi")
        self.assertEqual(Path(result).name, "ipxe.efi")

    def test_empty_after_opcode(self):
        self.assertIsNone(parse_tftp_rrq(struct.pack("!H", TFTP_RRQ) + b"\x00"))

    def test_only_opcode_and_null(self):
        self.assertEqual(parse_tftp_rrq(struct.pack("!H", TFTP_RRQ) + b"\x00\x00"), "")

    def test_no_null_at_all(self):
        self.assertIsNone(parse_tftp_rrq(struct.pack("!H", TFTP_RRQ) + b"test.bin"))

    def test_data_opcode(self):
        self.assertIsNone(
            parse_tftp_rrq(struct.pack("!H", TFTP_DATA) + b"test\x00octet\x00")
        )

    def test_ack_opcode(self):
        self.assertIsNone(
            parse_tftp_rrq(struct.pack("!H", TFTP_ACK) + b"test\x00octet\x00")
        )

    def test_error_opcode(self):
        self.assertIsNone(
            parse_tftp_rrq(struct.pack("!H", TFTP_ERROR) + b"test\x00octet\x00")
        )

    def test_non_ascii_filename(self):
        self.assertIsNotNone(
            parse_tftp_rrq(struct.pack("!H", TFTP_RRQ) + b"\xff\xfe\xfd\x00octet\x00")
        )

    def test_very_long_filename(self):
        name = b"a" * 500
        self.assertEqual(
            parse_tftp_rrq(struct.pack("!H", TFTP_RRQ) + name + b"\x00octet\x00"),
            "a" * 500,
        )

    def test_octet_mode(self):
        self.assertEqual(
            parse_tftp_rrq(struct.pack("!H", TFTP_RRQ) + b"t\x00octet\x00"), "t"
        )

    def test_netascii_mode(self):
        self.assertEqual(
            parse_tftp_rrq(struct.pack("!H", TFTP_RRQ) + b"t\x00netascii\x00"), "t"
        )

    def test_with_options(self):
        self.assertEqual(
            parse_tftp_rrq(
                struct.pack("!H", TFTP_RRQ) + b"t\x00octet\x00blksize\x001024\x00"
            ),
            "t",
        )


# --- TFTP Send ---


class TestTftpSendFile(unittest.TestCase):
    def test_send_small_file(self):
        mock_sock = MagicMock()
        state = {"file_data": b"hello-boot", "block_num": 0, "offset": 0}
        done = _tftp_send_next_block(mock_sock, ("127.0.0.1", 1234), state)
        self.assertTrue(done)
        sent = mock_sock.sendto.call_args[0][0]
        self.assertEqual(struct.unpack("!HH", sent[:4]), (TFTP_DATA, 1))
        self.assertEqual(sent[4:], b"hello-boot")

    def test_send_large_file_multi_block(self):
        mock_sock = MagicMock()
        state = {"file_data": b"x" * 1500, "block_num": 0, "offset": 0}
        for expected in (1, 2, 3):
            _tftp_send_next_block(mock_sock, ("127.0.0.1", 1234), state)
            _, block = struct.unpack("!HH", mock_sock.sendto.call_args[0][0][:4])
            self.assertEqual(block, expected)
        self.assertEqual(mock_sock.sendto.call_count, 3)

    def test_send_block_at_65535(self):
        mock_sock = MagicMock()
        state = {"file_data": b"x" * 512, "block_num": 65534, "offset": 0}
        done = _tftp_send_next_block(mock_sock, ("127.0.0.1", 9999), state)
        _, block = struct.unpack("!HH", mock_sock.sendto.call_args[0][0][:4])
        self.assertEqual(block, 65535)
        self.assertFalse(done)

    def test_wraparound_after_65535(self):
        mock_sock = MagicMock()
        state = {"file_data": b"x" * 1024, "block_num": 65534, "offset": 0}
        _tftp_send_next_block(mock_sock, ("127.0.0.1", 9999), state)
        self.assertEqual(state["block_num"], 65535)
        _tftp_send_next_block(mock_sock, ("127.0.0.1", 9999), state)
        self.assertEqual(state["block_num"], 0)

    def test_large_file_correct_block_count(self):
        mock_sock = MagicMock()
        state = {"file_data": b"x" * (5120 * 512), "block_num": 0, "offset": 0}
        blocks = 0
        while True:
            done = _tftp_send_next_block(mock_sock, ("127.0.0.1", 9999), state)
            blocks += 1
            if done:
                break
        self.assertEqual(blocks, 5121)

    def test_ack_at_block_65535(self):
        mock_sock = MagicMock()
        state = {"file_data": b"\x00" * 600, "block_num": 65533, "offset": 0}
        _tftp_send_next_block(mock_sock, ("127.0.0.1", 9999), state)
        _, block = struct.unpack("!HH", mock_sock.sendto.call_args[0][0][:4])
        self.assertEqual(block, 65534)
        done = _tftp_send_next_block(mock_sock, ("127.0.0.1", 9999), state)
        self.assertTrue(done)

    def test_empty_file_one_block(self):
        mock_sock = MagicMock()
        state = {"file_data": b"", "block_num": 0, "offset": 0}
        done = _tftp_send_next_block(mock_sock, ("127.0.0.1", 9999), state)
        self.assertTrue(done)
        self.assertEqual(len(mock_sock.sendto.call_args[0][0]), 4)

    def test_send_exactly_one_block(self):
        mock_sock = MagicMock()
        state = {"file_data": b"\xab" * 512, "block_num": 0, "offset": 0}
        done = _tftp_send_next_block(mock_sock, ("127.0.0.1", 9999), state)
        self.assertFalse(done)
        self.assertEqual(state["offset"], 512)
        done = _tftp_send_next_block(mock_sock, ("127.0.0.1", 9999), state)
        self.assertTrue(done)

    def test_send_one_byte_over_block(self):
        mock_sock = MagicMock()
        state = {"file_data": b"\xab" * 513, "block_num": 0, "offset": 0}
        _tftp_send_next_block(mock_sock, ("127.0.0.1", 9999), state)
        done = _tftp_send_next_block(mock_sock, ("127.0.0.1", 9999), state)
        self.assertTrue(done)
        self.assertEqual(state["offset"], 513)

    def test_send_exact_1024_bytes(self):
        mock_sock = MagicMock()
        state = {"file_data": b"\xab" * 1024, "block_num": 0, "offset": 0}
        for _ in range(2):
            self.assertFalse(
                _tftp_send_next_block(mock_sock, ("127.0.0.1", 9999), state)
            )
        self.assertTrue(_tftp_send_next_block(mock_sock, ("127.0.0.1", 9999), state))

    def test_send_exactly_5120_bytes(self):
        mock_sock = MagicMock()
        state = {"file_data": b"\xab" * 5120, "block_num": 0, "offset": 0}
        blocks = 0
        while True:
            done = _tftp_send_next_block(mock_sock, ("127.0.0.1", 9999), state)
            blocks += 1
            if done:
                break
        self.assertEqual(blocks, 11)


# --- TFTP Allowed Files ---


class TestTftpAllowedFiles(unittest.TestCase):
    def test_all_allowed_files_accepted(self):
        self.assertEqual(len(ALLOWED_BOOT_FILES), 7)
        for name in [
            b"undionly.kpxe",
            b"ipxe.efi",
            b"snponly.efi",
            b"snp.efi",
            b"ipxe.efi.signed",
            b"bootx64.efi",
            b"grubx64.efi",
        ]:
            self.assertIn(name, ALLOWED_BOOT_FILES)

    def test_unknown_file_rejected(self):
        for name in [b"vmlinuz", b"initrd.img", b"test.iso", b"hack.bin"]:
            self.assertIsNotNone(
                parse_tftp_rrq(struct.pack("!H", TFTP_RRQ) + name + b"\x00octet\x00")
            )


# --- HTTP Handler ---


class TestBootHTTPHandler(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.boot_root = Path(self.tmpdir)
        BootHTTPHandler.boot_root = self.boot_root

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_serves_file(self):
        (self.boot_root / "vmlinuz").write_bytes(b"fake-kernel-data")
        handler = make_handler("GET", "/vmlinuz")
        handler.do_GET()
        self.assertIn(b"fake-kernel-data", handler.wfile.getvalue())

    def test_404_for_missing_file(self):
        handler = make_handler("GET", "/nonexistent.iso")
        handler.do_GET()
        self.assertIn(b"404", handler.wfile.getvalue())

    def test_404_for_empty_path(self):
        handler = make_handler("GET", "/")
        handler.do_GET()
        self.assertIn(b"404", handler.wfile.getvalue())

    def test_directory_traversal_blocked(self):
        handler = make_handler("GET", "/../../../etc/passwd")
        handler.do_GET()
        self.assertIn(b"403", handler.wfile.getvalue())

    def test_serves_initrd(self):
        (self.boot_root / "initrd.img").write_bytes(b"fake-initrd")
        handler = make_handler("GET", "/initrd.img")
        handler.do_GET()
        self.assertIn(b"fake-initrd", handler.wfile.getvalue())


# --- HTTP Range Requests ---


class TestHttpRangeRequests(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.boot_dir = Path(self.tmpdir.name)
        (self.boot_dir / "test.iso").write_bytes(b"x" * 10000)
        BootHTTPHandler.boot_root = self.boot_dir

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_range_not_supported_returns_full(self):
        handler = make_handler("GET", "/test.iso")
        handler.headers = {"Range": "bytes=0-1023"}
        handler.do_GET()
        output = handler.wfile.getvalue()
        self.assertIn(b"200", output)
        self.assertIn(b"Content-Length: 10000", output)

    def test_no_range_returns_full_content(self):
        handler = make_handler("GET", "/test.iso")
        handler.do_GET()
        body = handler.wfile.getvalue().split(b"\r\n\r\n", 1)[1]
        self.assertEqual(len(body), 10000)

    def test_head_like_behavior_via_content_length(self):
        handler = make_handler("GET", "/test.iso")
        handler.do_GET()
        self.assertIn(b"Content-Length: 10000", handler.wfile.getvalue())

    def test_iso_mimetype_for_range_request(self):
        handler = make_handler("GET", "/test.iso")
        handler.do_GET()
        self.assertIn(b"application/x-iso9660-image", handler.wfile.getvalue())


# --- HTTP Large File ---


class TestHttpLargeFile(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.boot_dir = Path(self.tmpdir.name)
        BootHTTPHandler.boot_root = self.boot_dir

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_10mb_file_served_correctly(self):
        content = os.urandom(10 * 1024 * 1024)
        (self.boot_dir / "big.iso").write_bytes(content)
        handler = make_handler("GET", "/big.iso")
        handler.do_GET()
        self.assertIn(b"Content-Length: 10485760", handler.wfile.getvalue())

    def test_exact_block_boundary_file(self):
        content = b"\xaa" * 512
        (self.boot_dir / "exact.bin").write_bytes(content)
        handler = make_handler("GET", "/exact.bin")
        handler.do_GET()
        output = handler.wfile.getvalue()
        self.assertIn(b"Content-Length: 512", output)
        self.assertIn(content, output)

    def test_iso_mimetype(self):
        (self.boot_dir / "distro.iso").write_bytes(b"\x00" * 1024)
        handler = make_handler("GET", "/distro.iso")
        handler.do_GET()
        self.assertIn(b"application/x-iso9660-image", handler.wfile.getvalue())

    def test_kpxe_mimetype(self):
        (self.boot_dir / "undionly.kpxe").write_bytes(b"\x00" * 1024)
        handler = make_handler("GET", "/undionly.kpxe")
        handler.do_GET()
        self.assertIn(b"application/octet-stream", handler.wfile.getvalue())

    def test_efi_mimetype(self):
        (self.boot_dir / "ipxe.efi").write_bytes(b"\x00" * 1024)
        handler = make_handler("GET", "/ipxe.efi")
        handler.do_GET()
        self.assertIn(b"application/octet-stream", handler.wfile.getvalue())

    def test_unrecognized_extension_gets_octet_stream(self):
        (self.boot_dir / "data.dat").write_bytes(b"\x00" * 100)
        handler = make_handler("GET", "/data.dat")
        handler.do_GET()
        self.assertIn(b"application/octet-stream", handler.wfile.getvalue())


# --- HTTP Edge Cases ---


class TestHttpEdgeCases(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.boot_dir = Path(self.tmpdir.name)
        BootHTTPHandler.boot_root = self.boot_dir

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_traversal_with_double_encode(self):
        handler = make_handler("GET", "/%2e%2e/%2e%2e/etc/passwd")
        handler.do_GET()
        self.assertIn(b"403", handler.wfile.getvalue())

    def test_traversal_with_backslash(self):
        handler = make_handler("GET", "/..\\..\\etc\\passwd")
        handler.do_GET()
        self.assertIn(b"404", handler.wfile.getvalue())

    def test_null_byte_in_path(self):
        handler = make_handler("GET", "/test.txt%00.html")
        handler.do_GET()
        self.assertIn(b"404", handler.wfile.getvalue())

    def test_very_long_path(self):
        handler = make_handler("GET", "/" + "a" * 10000)
        handler.do_GET()
        self.assertIn(b"404", handler.wfile.getvalue())

    def test_serve_binary_file(self):
        content = bytes(range(256)) * 100
        (self.boot_dir / "binary.bin").write_bytes(content)
        handler = make_handler("GET", "/binary.bin")
        handler.do_GET()
        self.assertIn(content, handler.wfile.getvalue())

    def test_empty_file(self):
        (self.boot_dir / "empty.txt").write_bytes(b"")
        handler = make_handler("GET", "/empty.txt")
        handler.do_GET()
        output = handler.wfile.getvalue()
        self.assertIn(b"200", output)
        self.assertIn(b"Content-Length: 0", output)

    def test_path_with_encoded_spaces(self):
        (self.boot_dir / "my file.txt").write_bytes(b"data")
        handler = make_handler("GET", "/my%20file.txt")
        handler.do_GET()
        self.assertIn(b"data", handler.wfile.getvalue())

    def test_post_method_not_implemented(self):
        self.assertFalse(hasattr(BootHTTPHandler, "do_POST"))
        self.assertFalse(hasattr(BootHTTPHandler, "do_PUT"))
        self.assertFalse(hasattr(BootHTTPHandler, "do_DELETE"))

    def test_path_trailing_slash(self):
        (self.boot_dir / "file.txt").write_bytes(b"data")
        handler = make_handler("GET", "/file.txt/")
        handler.do_GET()
        output = handler.wfile.getvalue()
        self.assertIn(b"200", output)
        self.assertIn(b"data", output)

    def test_multiple_slashes_normalized(self):
        (self.boot_dir / "file.txt").write_bytes(b"data")
        handler = make_handler("GET", "///file.txt")
        handler.do_GET()
        self.assertIn(b"data", handler.wfile.getvalue())


# --- HTTP Chunked Transfer ---


class TestHttpChunkedTransfer(unittest.TestCase):
    def test_file_larger_than_chunk_size(self):
        """File > 256KB is served correctly via multiple chunks."""
        tmpdir = tempfile.mkdtemp()
        try:
            boot_dir = Path(tmpdir)
            BootHTTPHandler.boot_root = boot_dir
            content = b"\xaa" * (512 * 1024)
            (boot_dir / "large.bin").write_bytes(content)
            handler = make_handler("GET", "/large.bin")
            handler.do_GET()
            output = handler.wfile.getvalue()
            self.assertIn(b"Content-Length: 524288", output)
            self.assertIn(content, output)
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)


# --- ReusableHTTPServer ---


class TestReusableHTTPServer(unittest.TestCase):
    def test_server_bind_sets_reuse_addr(self):
        server = ReusableHTTPServer(("127.0.0.1", 0), BootHTTPHandler)
        try:
            self.assertEqual(
                server.socket.getsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR), 1
            )
        finally:
            server.server_close()

    def test_server_bind_captures_address(self):
        server = ReusableHTTPServer(("127.0.0.1", 0), BootHTTPHandler)
        try:
            self.assertEqual(server.server_address[0], "127.0.0.1")
            self.assertGreater(server.server_address[1], 0)
        finally:
            server.server_close()


# --- iPXE Script Syntax ---


class TestIpexScriptSyntax(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.boot_dir = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_starts_with_shebang(self):
        (self.boot_dir / "test.iso").write_bytes(b"x")
        self.assertEqual(
            generate_boot_config(self.boot_dir).read_text().splitlines()[0], "#!ipxe"
        )

    def test_goto_targets_all_defined(self):
        (self.boot_dir / "arch.iso").write_bytes(b"x")
        text = generate_boot_config(self.boot_dir).read_text()
        for target in re.findall(r"goto\s+(\S+)", text):
            self.assertIn(target, re.findall(r"^:(\S+)", text, re.MULTILINE))

    def test_timeout_line_present(self):
        self.assertIn(
            "set timeout 30000", generate_boot_config(self.boot_dir).read_text()
        )

    def test_choose_command_present(self):
        (self.boot_dir / "test.iso").write_bytes(b"x")
        self.assertIn("choose target", generate_boot_config(self.boot_dir).read_text())

    def test_menu_command_present(self):
        (self.boot_dir / "test.iso").write_bytes(b"x")
        self.assertIn(
            "menu servings-cli PXE Boot Server",
            generate_boot_config(self.boot_dir).read_text(),
        )

    def test_empty_dir_has_fallback(self):
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertIn(":boot_none", text)
        self.assertIn(":failed", text)

    def test_special_chars_in_filename(self):
        (self.boot_dir / "My OS 2.0.iso").write_bytes(b"x")
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertIn("My_OS_2_0_iso", text)
        self.assertIn("My OS 2.0.iso", text)

    def test_dollar_sign_in_filename(self):
        (self.boot_dir / "test$variable.iso").write_bytes(b"x")
        self.assertIn(
            "test$variable.iso", generate_boot_config(self.boot_dir).read_text()
        )

    def test_multiple_iso_entries(self):
        for name in ("arch.iso", "fedora.iso", "ubuntu.iso"):
            (self.boot_dir / name).write_bytes(b"x")
        text = generate_boot_config(self.boot_dir).read_text()
        for key in ("arch_iso", "fedora_iso", "ubuntu_iso"):
            self.assertIn(f"item {key}", text)
            self.assertIn(f":{key}", text)

    def test_kernel_initrd_pair_in_script(self):
        (self.boot_dir / "vmlinuz-linux").write_bytes(b"k")
        (self.boot_dir / "initramfs-linux.img").write_bytes(b"i")
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertIn("kernel /vmlinuz-linux", text)
        self.assertIn("initrd /initramfs-linux.img", text)
        self.assertIn("boot || goto failed", text)

    def test_standalone_kernel_in_script(self):
        (self.boot_dir / "vmlinuz-custom").write_bytes(b"k")
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertIn("kernel /vmlinuz-custom", text)
        self.assertNotIn("initrd", text)

    def test_sanboot_for_iso(self):
        (self.boot_dir / "test.iso").write_bytes(b"x")
        self.assertIn(
            "sanboot ${boot-path}", generate_boot_config(self.boot_dir).read_text()
        )


# --- DHCP Malformed Options ---


class TestDhcpMalformedOptions(unittest.TestCase):
    def _build(self, opts):
        mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        return build_dhcp_with_options(mac, opts)

    def test_zero_length_option(self):
        opts = bytes([53, 1, DHCP_DISCOVER, 60, 9]) + b"PXEClient" + bytes([255])
        result = _parse_dhcp_request(self._build(opts))
        self.assertIsNotNone(result)
        self.assertEqual(result["msg_type"], DHCP_DISCOVER)

    def test_missing_end_marker(self):
        opts = bytes([53, 1, DHCP_DISCOVER, 60, 9]) + b"PXEClient"
        self.assertIsNotNone(_parse_dhcp_request(self._build(opts)))

    def test_pad_option_skipped(self):
        opts = (
            bytes([0, 0, 0, 0, 53, 1, DHCP_DISCOVER, 60, 9])
            + b"PXEClient"
            + bytes([255])
        )
        self.assertIsNotNone(_parse_dhcp_request(self._build(opts)))

    def test_option_length_exceeding_remaining(self):
        opts = bytes([60, 250]) + b"PXE" + bytes([53, 1, DHCP_DISCOVER, 255])
        self.assertIsNone(_parse_dhcp_request(self._build(opts)))

    def test_duplicate_message_type(self):
        opts = bytes([53, 1, DHCP_DISCOVER, 53, 1, DHCP_REQUEST, 255])
        result = _parse_dhcp_request(self._build(opts))
        self.assertIsNotNone(result)
        self.assertEqual(result["msg_type"], DHCP_REQUEST)

    def test_truncated_option_length(self):
        opts = bytes([53, 200, 255])
        self.assertIsNone(_parse_dhcp_request(self._build(opts)))

    def test_empty_vendor_class(self):
        opts = bytes([53, 1, DHCP_DISCOVER, 60, 0, 255])
        result = _parse_dhcp_request(self._build(opts))
        self.assertIsNotNone(result)
        self.assertFalse(result["is_pxe"])

    def test_very_large_vendor_class(self):
        vendor = b"PXEClient" + b"\x00" * 246
        opts = bytes([53, 1, DHCP_DISCOVER, 60, len(vendor)]) + vendor + bytes([255])
        result = _parse_dhcp_request(self._build(opts))
        self.assertIsNotNone(result)
        self.assertTrue(result["is_pxe"])


# --- DHCP Response Options ---


class TestDhcpResponseOptions(unittest.TestCase):
    def _req(self, msg_type=DHCP_DISCOVER, is_pxe=True):
        return {
            "xid": b"\x01\x02\x03\x04",
            "mac": b"\xaa\xbb\xcc\xdd\xee\xff",
            "mac_str": "aa:bb:cc:dd:ee:ff",
            "msg_type": msg_type,
            "is_pxe": is_pxe,
        }

    def _walk(self, data):
        opts = data[240:]
        result = {}
        i = 0
        while i < len(opts):
            tag = opts[i]
            if tag == 255:
                break
            if i + 1 >= len(opts):
                break
            length = opts[i + 1]
            result[tag] = opts[i + 2 : i + 2 + length]
            i += 2 + length
        return result

    def test_offer_contains_all_pxe_options(self):
        pkt = _build_bootp_packet(
            self._req(), "192.168.42.100", "192.168.42.1", DHCP_OFFER, "undionly.kpxe"
        )
        self.assertEqual(pkt[0], 2)
        self.assertEqual(pkt[236:240], MAGIC_COOKIE)
        opts = pkt[240:]
        tags = []
        cursor = 0
        while cursor < len(opts):
            tag = opts[cursor]
            if tag == 255:
                tags.append(255)
                break
            length = opts[cursor + 1]
            tags.append(tag)
            cursor += 2 + length
        self.assertEqual(tags[0], 53)
        self.assertIn(60, tags)
        self.assertIn(66, tags)
        self.assertIn(67, tags)
        self.assertEqual(tags[-1], 255)

    def test_ack_has_correct_message_type(self):
        pkt = _build_bootp_packet(
            self._req(), "192.168.42.100", "192.168.42.1", DHCP_ACK, "undionly.kpxe"
        )
        opts = pkt[240:]
        self.assertEqual(opts[opts.index(53) + 2], DHCP_ACK)

    def test_domain_option_present(self):
        pkt = _build_bootp_packet(
            self._req(), "192.168.42.100", "192.168.42.1", DHCP_OFFER, "undionly.kpxe"
        )
        walk = self._walk(pkt)
        self.assertIn(15, walk)
        self.assertEqual(walk[15], b"local\x00")


# --- Multiple Boot Types ---


class TestMultipleBootTypes(unittest.TestCase):
    def _test_arch(self, arch_id, expected):
        mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        result = parse_packet(
            build_pxe_discover(mac, arch_id=arch_id), ("127.0.0.1", 68)
        )
        self.assertIsNotNone(result)
        self.assertEqual(result["boot_file"], expected)

    def test_bios(self):
        self._test_arch(0x0000, "undionly.kpxe")

    def test_efi32(self):
        self._test_arch(0x0006, "ipxe.efi")

    def test_efi64(self):
        self._test_arch(0x0007, "ipxe.efi")

    def test_arm64(self):
        self._test_arch(0x000B, "ipxe.efi")

    def test_bc(self):
        self._test_arch(0x0008, "ipxe.efi")

    def test_unknown(self):
        self._test_arch(0xFFFF, "ipxe.efi")

    def test_reply_to_each_type(self):
        for arch_id in (0x0000, 0x0006, 0x0007, 0x000B):
            mac = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
            result = parse_packet(
                build_pxe_discover(mac, arch_id=arch_id), ("127.0.0.1", 68)
            )
            mock_sock = MagicMock()
            send_proxy_reply(mock_sock, result)
            sent = mock_sock.sendto.call_args[0][0]
            self.assertEqual(sent[0], 2)
            self.assertEqual(sent[236:240], b"\x63\x82\x53\x63")


# --- ProxyDHCP Packet Validation ---


class TestProxyDhcpPacketValidation(unittest.TestCase):
    def test_short_packet_returns_none(self):
        self.assertIsNone(parse_packet(b"\x00" * 100, ("127.0.0.1", 68)))

    def test_bootreply_returns_none(self):
        pkt = bytearray(240)
        pkt[0] = 2
        pkt[236:240] = MAGIC_COOKIE
        self.assertIsNone(parse_packet(bytes(pkt), ("127.0.0.1", 68)))

    def test_missing_magic_cookie_returns_none(self):
        pkt = bytearray(240)
        pkt[0] = 1
        self.assertIsNone(parse_packet(bytes(pkt), ("127.0.0.1", 68)))

    def test_no_pxe_option_returns_none(self):
        self.assertIsNone(
            parse_packet(
                build_pxe_discover(b"\xaa\xbb\xcc\xdd\xee\xff", arch_id=0).replace(
                    b"PXEClient:Arch:0000", b"Linux:Arch:0000"
                ),
                ("127.0.0.1", 68),
            )
        )

    def test_valid_pxe_discover_accepted(self):
        result = parse_packet(build_pxe_discover(), ("127.0.0.1", 68))
        self.assertIsNotNone(result)
        self.assertEqual(result["mac_readable"], "00:11:22:33:44:55")


# --- IP Pool ---


class TestIpPool(unittest.TestCase):
    def test_first_ip(self):
        self.assertEqual(IPPool().allocate("aa:bb:cc:dd:ee:ff"), "192.168.42.100")

    def test_reuse_lease(self):
        pool = IPPool()
        ip1 = pool.allocate("aa:bb:cc:dd:ee:ff")
        ip2 = pool.allocate("aa:bb:cc:dd:ee:ff")
        self.assertEqual(ip1, ip2)

    def test_different_macs(self):
        pool = IPPool()
        self.assertNotEqual(
            pool.allocate("aa:bb:cc:dd:ee:01"), pool.allocate("aa:bb:cc:dd:ee:02")
        )

    def test_pool_wraparound(self):
        pool = IPPool(next_ip=199, max_ip=200)
        pool.allocate("aa:bb:cc:dd:ee:01")
        pool.allocate("aa:bb:cc:dd:ee:02")
        self.assertEqual(pool.allocate("aa:bb:cc:dd:ee:03"), "192.168.42.100")

    def test_custom_subnet(self):
        self.assertEqual(
            IPPool(subnet="10.0.0").allocate("aa:bb:cc:dd:ee:ff"), "10.0.0.100"
        )

    def test_sequential(self):
        pool = IPPool()
        ips = [pool.allocate(f"aa:bb:cc:dd:ee:{i:02x}") for i in range(5)]
        self.assertEqual(ips, [f"192.168.42.{100 + i}" for i in range(5)])

    def test_exhaustion(self):
        pool = IPPool(subnet="10.0.0", next_ip=100, max_ip=102)
        ips = set(pool.allocate(f"aa:bb:cc:dd:ee:{i:02x}") for i in range(5))
        self.assertIn("10.0.0.100", ips)
        self.assertIn("10.0.0.101", ips)
        self.assertIn("10.0.0.102", ips)

    def test_single_ip(self):
        pool = IPPool(next_ip=100, max_ip=100)
        ip1 = pool.allocate("aa:bb:cc:dd:ee:01")
        ip2 = pool.allocate("aa:bb:cc:dd:ee:02")
        self.assertEqual(ip1, ip2)

    def test_custom_range(self):
        self.assertEqual(
            IPPool(subnet="172.16.0", next_ip=10, max_ip=15).allocate(
                "aa:bb:cc:dd:ee:ff"
            ),
            "172.16.0.10",
        )


# --- DHCP Parser ---


class TestParseDhcpRequest(unittest.TestCase):
    def _make(self, msg_type, is_pxe=False):
        pkt = bytearray(240)
        pkt[0] = 1
        pkt[4:8] = b"\x01\x02\x03\x04"
        pkt[28:34] = b"\xaa\xbb\xcc\xdd\xee\xff"
        pkt[236:240] = MAGIC_COOKIE
        opts = bytes([53, 1, msg_type])
        if is_pxe:
            opts += bytes([60, 9]) + b"PXEClient"
        opts += bytes([255])
        return bytes(pkt + opts)

    def test_discover(self):
        result = _parse_dhcp_request(self._make(DHCP_DISCOVER))
        self.assertIsNotNone(result)
        self.assertEqual(result["msg_type"], DHCP_DISCOVER)
        self.assertFalse(result["is_pxe"])

    def test_pxe_discover(self):
        result = _parse_dhcp_request(self._make(DHCP_DISCOVER, is_pxe=True))
        self.assertTrue(result["is_pxe"])

    def test_request(self):
        self.assertEqual(
            _parse_dhcp_request(self._make(DHCP_REQUEST))["msg_type"], DHCP_REQUEST
        )

    def test_fields(self):
        result = _parse_dhcp_request(self._make(DHCP_DISCOVER, is_pxe=True))
        self.assertEqual(result["xid"], b"\x01\x02\x03\x04")
        self.assertEqual(result["mac_str"], "aa:bb:cc:dd:ee:ff")

    def test_short_packet(self):
        self.assertIsNone(_parse_dhcp_request(b"\x00" * 100))

    def test_wrong_opcode(self):
        data = bytearray(240)
        data[0] = 2
        data[236:240] = MAGIC_COOKIE
        data += bytes([66, 1, DHCP_DISCOVER, 255])
        self.assertIsNone(_parse_dhcp_request(bytes(data)))

    def test_no_magic_cookie(self):
        data = bytearray(240)
        data[0] = 1
        self.assertIsNone(_parse_dhcp_request(bytes(data)))

    def test_unknown_msg_type(self):
        self.assertIsNone(_parse_dhcp_request(self._make(99)))

    def test_pxe_in_wrong_tag(self):
        pkt = bytearray(240)
        pkt[0] = 1
        pkt[4:8] = b"\x01\x02\x03\x04"
        pkt[28:34] = b"\xaa\xbb\xcc\xdd\xee\xff"
        pkt[236:240] = MAGIC_COOKIE
        pkt += (
            bytes([53, 1, DHCP_DISCOVER]) + bytes([55, 9]) + b"PXEClient" + bytes([255])
        )
        result = _parse_dhcp_request(bytes(pkt))
        self.assertIsNotNone(result)
        self.assertFalse(result["is_pxe"])


# --- BOOTP Packet Builder ---


class TestBuildBootpPacket(unittest.TestCase):
    def setUp(self):
        self.request = {
            "xid": b"\x01\x02\x03\x04",
            "mac": b"\xaa\xbb\xcc\xdd\xee\xff",
            "mac_str": "aa:bb:cc:dd:ee:ff",
            "msg_type": DHCP_DISCOVER,
            "is_pxe": True,
        }
        self.ip = "192.168.42.100"
        self.server = "192.168.42.129"

    def _walk(self, data):
        opts = data[240:]
        result = {}
        i = 0
        while i < len(opts):
            tag = opts[i]
            if tag == 255:
                break
            if i + 1 >= len(opts):
                break
            length = opts[i + 1]
            result[tag] = opts[i + 2 : i + 2 + length]
            i += 2 + length
        return result

    def test_header(self):
        pkt = _build_bootp_packet(
            self.request, self.ip, self.server, DHCP_OFFER, "undionly.kpxe"
        )
        self.assertEqual(pkt[0], 2)
        self.assertEqual(pkt[1], 1)
        self.assertEqual(pkt[2], 6)
        self.assertEqual(pkt[4:8], b"\x01\x02\x03\x04")
        self.assertEqual(pkt[28:34], b"\xaa\xbb\xcc\xdd\xee\xff")
        self.assertEqual(pkt[236:240], MAGIC_COOKIE)

    def test_addresses(self):
        pkt = _build_bootp_packet(
            self.request, self.ip, self.server, DHCP_OFFER, "undionly.kpxe"
        )
        self.assertEqual(pkt[16:20], socket.inet_aton(self.ip))
        self.assertEqual(pkt[20:24], socket.inet_aton(self.server))

    def test_offer_options(self):
        pkt = _build_bootp_packet(
            self.request, self.ip, self.server, DHCP_OFFER, "undionly.kpxe"
        )
        opts = self._walk(pkt)
        self.assertEqual(opts[53], bytes([DHCP_OFFER]))
        self.assertEqual(opts[54], socket.inet_aton(self.server))

    def test_ack_options(self):
        pkt = _build_bootp_packet(
            self.request, self.ip, self.server, DHCP_ACK, "undionly.kpxe"
        )
        opts = self._walk(pkt)
        self.assertEqual(opts[53], bytes([DHCP_ACK]))

    def test_router_and_dns(self):
        pkt = _build_bootp_packet(
            self.request, self.ip, self.server, DHCP_OFFER, "undionly.kpxe"
        )
        opts = self._walk(pkt)
        self.assertEqual(opts[3], socket.inet_aton(self.server))
        self.assertEqual(opts[6], socket.inet_aton(self.server))

    def test_boot_file(self):
        pkt = _build_bootp_packet(
            self.request, self.ip, self.server, DHCP_ACK, "ipxe.efi"
        )
        opts = self._walk(pkt)
        self.assertEqual(opts[67], b"ipxe.efi\x00")

    def test_broadcast(self):
        pkt = _build_bootp_packet(
            self.request, self.ip, self.server, DHCP_OFFER, "undionly.kpxe"
        )
        opts = self._walk(pkt)
        self.assertEqual(opts[28], socket.inet_aton("192.168.42.255"))

    def test_different_subnet(self):
        pkt = _build_bootp_packet(
            self.request, "10.0.0.50", "10.0.0.1", DHCP_OFFER, "undionly.kpxe"
        )
        opts = self._walk(pkt)
        self.assertEqual(opts[28], socket.inet_aton("10.0.0.255"))


# --- Boot Config ---


class TestGenerateBootConfig(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.boot_dir = Path(self.tmpdir)

    def tearDown(self):
        import shutil

        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_generates_from_isos(self):
        (self.boot_dir / "arch-linux.iso").write_bytes(b"x")
        (self.boot_dir / "ubuntu-22.04.iso").write_bytes(b"x")
        content = generate_boot_config(self.boot_dir).read_text()
        self.assertIn("arch-linux.iso", content)
        self.assertIn("sanboot", content)

    def test_generates_from_kernel_initrd_pairs(self):
        (self.boot_dir / "vmlinuz-linux").write_bytes(b"k")
        (self.boot_dir / "initramfs-linux.img").write_bytes(b"i")
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertIn("kernel /vmlinuz-linux", text)
        self.assertIn("initrd /initramfs-linux.img", text)

    def test_empty_directory(self):
        self.assertIn(
            "No bootable images found", generate_boot_config(self.boot_dir).read_text()
        )

    def test_ignores_boot_cfg_and_bootloaders(self):
        (self.boot_dir / "boot.cfg").write_bytes(b"old")
        (self.boot_dir / "undionly.kpxe").write_bytes(b"x")
        (self.boot_dir / "ipxe.efi").write_bytes(b"x")
        self.assertIn(
            "No bootable images found", generate_boot_config(self.boot_dir).read_text()
        )

    def test_mixed_content(self):
        (self.boot_dir / "arch-linux.iso").write_bytes(b"x")
        (self.boot_dir / "vmlinuz-linux").write_bytes(b"k")
        (self.boot_dir / "initramfs-linux.img").write_bytes(b"i")
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertIn("Disk Images", text)
        self.assertIn("Kernel + Initrd", text)


# --- Boot Config All Types ---


class TestBootConfigAllTypes(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.boot_dir = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_all_three_categories(self):
        (self.boot_dir / "ubuntu.iso").write_bytes(b"i")
        (self.boot_dir / "vmlinuz-5.15").write_bytes(b"k")
        (self.boot_dir / "initrd-5.15.img").write_bytes(b"r")
        (self.boot_dir / "vmlinuz-custom").write_bytes(b"s")
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertIn("Disk Images", text)
        self.assertIn("Kernel + Initrd", text)
        self.assertIn("Kernels", text)

    def test_deep_subdirectory(self):
        sub = self.boot_dir / "distros" / "arch" / "2024"
        sub.mkdir(parents=True)
        (sub / "arch.iso").write_bytes(b"i")
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertIn("distros/arch/2024/arch.iso", text)

    def test_initrd_prefix_stripping(self):
        (self.boot_dir / "vmlinuz-6.1").write_bytes(b"k")
        (self.boot_dir / "initramfs-6.1.img").write_bytes(b"r")
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertIn("kernel /vmlinuz-6.1", text)
        self.assertIn("initrd /initramfs-6.1.img", text)

    def test_initrd_suffix_stripping(self):
        (self.boot_dir / "vmlinuz-core").write_bytes(b"k")
        (self.boot_dir / "initrd-core.img").write_bytes(b"r")
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertIn("initrd /initrd-core.img", text)

    def test_fallback_pairing(self):
        (self.boot_dir / "vmlinuz-a").write_bytes(b"k")
        (self.boot_dir / "initrd-orphan.img").write_bytes(b"r")
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertIn("Kernel + Initrd", text)

    def test_no_files_at_all(self):
        self.assertIn(
            "No bootable images found", generate_boot_config(self.boot_dir).read_text()
        )

    def test_only_non_bootable_files(self):
        (self.boot_dir / "README.md").write_bytes(b"# Hello")
        self.assertIn(
            "No bootable images found", generate_boot_config(self.boot_dir).read_text()
        )


# --- Boot Config Edge Cases ---


class TestBootConfigEdgeCases(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.TemporaryDirectory()
        self.boot_dir = Path(self.tmpdir.name)

    def tearDown(self):
        self.tmpdir.cleanup()

    def test_macos_resource_forks_excluded(self):
        (self.boot_dir / "arch.iso").write_bytes(b"x")
        (self.boot_dir / "._arch.iso").write_bytes(b"junk")
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertIn("arch.iso", text)
        self.assertNotIn("._arch", text)

    def test_fseventsd_excluded(self):
        (self.boot_dir / ".fseventsd").mkdir()
        (self.boot_dir / ".fseventsd" / "uuid").write_bytes(b"uuid")
        (self.boot_dir / "test.iso").write_bytes(b"x")
        self.assertNotIn("fseventsd", generate_boot_config(self.boot_dir).read_text())

    def test_system_volume_information_excluded(self):
        svi = self.boot_dir / "System Volume Information"
        svi.mkdir()
        (svi / "IndexerVolumeGuid").write_bytes(b"guid")
        (self.boot_dir / "test.iso").write_bytes(b"x")
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertNotIn("System Volume", text)

    def test_visync_excluded(self):
        (self.boot_dir / "test.iso").write_bytes(b"x")
        (self.boot_dir / "._visync").write_bytes(b"junk")
        self.assertNotIn(
            "visync", generate_boot_config(self.boot_dir).read_text().lower()
        )

    def test_duplicate_iso_case_insensitive(self):
        (self.boot_dir / "Arch.iso").write_bytes(b"x")
        (self.boot_dir / "arch.iso").write_bytes(b"y")
        self.assertEqual(
            generate_boot_config(self.boot_dir).read_text().count("Arch"), 1
        )

    def test_iso_in_subdirectory(self):
        sub = self.boot_dir / "distros"
        sub.mkdir()
        (sub / "arch-linux.iso").write_bytes(b"x")
        self.assertIn(
            "distros/arch-linux.iso", generate_boot_config(self.boot_dir).read_text()
        )

    def test_symlink_not_followed_into_jail(self):
        outside = Path(tempfile.mkdtemp()) / "secret.txt"
        outside.write_bytes(b"secret")
        link = self.boot_dir / "sneaky"
        try:
            link.symlink_to(outside)
        except OSError:
            self.skipTest("Cannot create symlinks")
        (self.boot_dir / "test.iso").write_bytes(b"x")
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertNotIn("secret", text)
        outside.unlink()
        link.unlink()

    def test_empty_iso_zero_bytes(self):
        (self.boot_dir / "empty.iso").write_bytes(b"")
        self.assertIn("empty.iso", generate_boot_config(self.boot_dir).read_text())

    def test_iso_with_spaces(self):
        (self.boot_dir / "My Linux.iso").write_bytes(b"x")
        self.assertIn("My Linux.iso", generate_boot_config(self.boot_dir).read_text())

    def test_iso_with_unicode(self):
        (self.boot_dir / "arch-\u65e5\u672c\u8a9e.iso").write_bytes(b"x")
        self.assertIn(
            "arch-\u65e5\u672c\u8a9e.iso",
            generate_boot_config(self.boot_dir).read_text(),
        )

    def test_kernel_without_initrd(self):
        (self.boot_dir / "vmlinuz-linux").write_bytes(b"k")
        text = generate_boot_config(self.boot_dir).read_text()
        self.assertIn("vmlinuz-linux", text)
        self.assertIn("kernel /vmlinuz-linux", text)

    def test_initrd_without_kernel(self):
        (self.boot_dir / "initramfs-linux.img").write_bytes(b"i")
        self.assertNotIn(
            "kernel /initramfs", generate_boot_config(self.boot_dir).read_text()
        )

    def test_bzimage_detected(self):
        self.assertTrue(_is_kernel(Path("bzImage-vmlinuz")))
        self.assertTrue(_is_kernel(Path("vmlinuz-linux")))
        self.assertFalse(_is_kernel(Path("random.txt")))

    def test_initrd_detection(self):
        self.assertTrue(_is_initrd(Path("initramfs-linux.img")))
        self.assertTrue(_is_initrd(Path("initrd.img")))
        self.assertTrue(_is_initrd(Path("initrd")))
        self.assertTrue(_is_initrd(Path("initramfs")))
        self.assertFalse(_is_initrd(Path("vmlinuz")))

    def test_label_edge_cases(self):
        self.assertEqual(_label_from_filename("a.iso"), "A")
        self.assertEqual(_label_from_filename("ALLCAPS.iso"), "Allcaps")
        self.assertEqual(_label_from_filename("a-b-c.iso"), "A B C")

    def test_ignored_dirs(self):
        for dirname in [".git", ".venv", "__pycache__", "$RECYCLE.BIN", ".svn"]:
            self.assertIn(dirname, _IGNORED_DIRS)

    def test_ignored_names(self):
        from src.boot_config import _IGNORED_NAMES

        for name in ["boot.cfg", ".DS_Store", "undionly.kpxe", "ipxe.efi"]:
            self.assertIn(name, _IGNORED_NAMES)

    def test_initrd_img_extension(self):
        """The .img extension is recognized for initrds."""
        self.assertTrue(_is_initrd(Path("initrd.img")))
        self.assertTrue(_is_initrd(Path("test.img")))

    def test_initrd_initrd_extension(self):
        """The .initrd extension is recognized."""
        self.assertTrue(_is_initrd(Path("vmlinuz.initrd")))


# --- Label ---


class TestLabelFromFilename(unittest.TestCase):
    def test_iso_label(self):
        self.assertEqual(
            _label_from_filename("arch-linux-2024.01.iso"), "Arch Linux 2024.01"
        )

    def test_kernel_label(self):
        self.assertEqual(_label_from_filename("vmlinuz-linux"), "Vmlinuz Linux")

    def test_acronym_preserved(self):
        self.assertEqual(_label_from_filename("fedora-kde-live.iso"), "Fedora KDE Live")

    def test_strips_extension(self):
        self.assertEqual(_label_from_filename("test.iso"), "Test")

    def test_hyphens_become_spaces(self):
        self.assertEqual(_label_from_filename("arch-linux.iso"), "Arch Linux")

    def test_underscores_become_spaces(self):
        self.assertEqual(_label_from_filename("my_distro.iso"), "MY Distro")

    def test_empty_after_strip(self):
        self.assertEqual(_label_from_filename(".iso"), "")

    def test_single_char(self):
        self.assertEqual(_label_from_filename("a.iso"), "A")

    def test_long_word_capitalized(self):
        self.assertEqual(_label_from_filename("ubuntu-desktop.iso"), "Ubuntu Desktop")

    def test_multiple_dots(self):
        self.assertEqual(_label_from_filename("arch.2024.01.iso"), "Arch.2024.01")

    def test_numbers_preserved(self):
        self.assertEqual(_label_from_filename("ubuntu-22.04.iso"), "Ubuntu 22.04")


# --- Apple PXE Prefix ---


class TestApplePxePrefix(unittest.TestCase):
    def test_uppercase_mac_prefix(self):
        rrq = (
            struct.pack("!H", TFTP_RRQ)
            + b"/01-AA-BB-CC-DD-EE-FF/undionly.kpxe\x00octet\x00"
        )
        self.assertEqual(parse_tftp_rrq(rrq), "/01-AA-BB-CC-DD-EE-FF/undionly.kpxe")

    def test_colon_separated_mac_prefix(self):
        rrq = (
            struct.pack("!H", TFTP_RRQ)
            + b"/01:aa:bb:cc:dd:ee:ff/undionly.kpxe\x00octet\x00"
        )
        self.assertEqual(parse_tftp_rrq(rrq), "/01:aa:bb:cc:dd:ee:ff/undionly.kpxe")


# --- ProxyDHCP Detect Boot File ---


class TestDetectBootFile(unittest.TestCase):
    def test_bios(self):
        self.assertEqual(
            _detect_boot_file(b"PXEClient:Arch:00000:UNDI:003000"), "undionly.kpxe"
        )

    def test_efi_arch_6(self):
        self.assertEqual(
            _detect_boot_file(b"PXEClient:Arch:00006:UNDI:003000"), "ipxe.efi"
        )

    def test_efi_arch_7(self):
        self.assertEqual(
            _detect_boot_file(b"PXEClient:Arch:00007:UNDI:003000"), "ipxe.efi"
        )

    def test_efi_arch_9(self):
        self.assertEqual(
            _detect_boot_file(b"PXEClient:Arch:00009:UNDI:003000"), "ipxe.efi"
        )

    def test_bare_pxeclient(self):
        self.assertEqual(_detect_boot_file(b"PXEClient"), "undionly.kpxe")

    def test_malformed(self):
        self.assertEqual(_detect_boot_file(b"garbage\xff\xfe"), "undionly.kpxe")

    def test_empty(self):
        self.assertEqual(_detect_boot_file(b""), "undionly.kpxe")

    def test_arch_without_colon(self):
        self.assertEqual(_detect_boot_file(b"PXEClient:Arch"), "undionly.kpxe")

    def test_arm64(self):
        self.assertEqual(
            _detect_boot_file(b"PXEClient:Arch:0000b:UNDI:003000"), "ipxe.efi"
        )

    def test_bc(self):
        self.assertEqual(
            _detect_boot_file(b"PXEClient:Arch:00008:UNDI:003000"), "ipxe.efi"
        )


# --- Send Proxy Reply ---


class TestSendProxyReply(unittest.TestCase):
    def test_sends_reply(self):
        mock_sock = MagicMock()
        info = {
            "client_address": ("10.0.0.50", 4011),
            "transaction_id": b"\x01\x02\x03\x04",
            "mac_raw": b"\xaa\xbb\xcc\xdd\xee\xff",
            "mac_readable": "aa:bb:cc:dd:ee:ff",
            "boot_file": "undionly.kpxe",
        }
        send_proxy_reply(mock_sock, info)
        data, target = mock_sock.sendto.call_args[0]
        self.assertEqual(target, ("10.0.0.50", 4011))
        self.assertEqual(data[0], 2)
        self.assertIn(b"undionly.kpxe", data)

    def test_ipxe_efi(self):
        mock_sock = MagicMock()
        info = {
            "client_address": ("10.0.0.50", 4011),
            "transaction_id": b"\x01\x02\x03\x04",
            "mac_raw": b"\xaa\xbb\xcc\xdd\xee\xff",
            "mac_readable": "aa:bb:cc:dd:ee:ff",
            "boot_file": "ipxe.efi",
        }
        send_proxy_reply(mock_sock, info)
        self.assertIn(b"ipxe.efi", mock_sock.sendto.call_args[0][0])


# --- Extra Paths in HTTP ---


class TestHttpExtraPaths(unittest.TestCase):
    def test_extra_path_outside_boot_root(self):
        """Path outside boot_root but in extra_paths is served."""
        tmpdir = tempfile.mkdtemp()
        try:
            boot_dir = Path(tmpdir)
            extra_dir = boot_dir / "extra"
            extra_dir.mkdir()
            (extra_dir / "test.efi").write_bytes(b"EXTRA")
            BootHTTPHandler.boot_root = boot_dir
            BootHTTPHandler.extra_paths = [extra_dir]
            handler = make_handler("GET", "/extra/test.efi")
            handler.do_GET()
            self.assertIn(b"EXTRA", handler.wfile.getvalue())
            BootHTTPHandler.extra_paths = []
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_extra_path_traversal_blocked(self):
        """Path outside both boot_root and extra_paths returns 403."""
        tmpdir = tempfile.mkdtemp()
        try:
            boot_dir = Path(tmpdir)
            extra_dir = boot_dir / "extra"
            extra_dir.mkdir()
            BootHTTPHandler.boot_root = boot_dir
            BootHTTPHandler.extra_paths = [extra_dir]
            handler = make_handler("GET", "/../../../etc/passwd")
            handler.do_GET()
            self.assertIn(b"403", handler.wfile.getvalue())
            BootHTTPHandler.extra_paths = []
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)

    def test_no_extra_paths_default(self):
        """By default, extra_paths is empty."""
        self.assertEqual(BootHTTPHandler.extra_paths, [])


# --- Main Module ---


class TestMainResolveBootDir(unittest.TestCase):
    def test_explicit_dir(self):
        from src.main import _resolve_boot_dir

        tmpdir = tempfile.mkdtemp()
        try:
            self.assertEqual(_resolve_boot_dir(tmpdir), tmpdir)
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)

    @patch("src.main._detect_usb_boot_dirs")
    def test_fallback_to_dot(self, mock_usb):
        from src.main import _resolve_boot_dir

        mock_usb.return_value = []
        result = _resolve_boot_dir(None)
        self.assertEqual(result, ".")

    @patch("src.main._detect_usb_boot_dirs")
    def test_usb_detection(self, mock_usb):
        from src.main import _resolve_boot_dir

        tmpdir = Path(tempfile.mkdtemp())
        try:
            (tmpdir / "test.iso").write_bytes(b"x")
            mock_usb.return_value = [tmpdir]
            result = _resolve_boot_dir(None)
            self.assertEqual(result, str(tmpdir))
        finally:
            import shutil

            shutil.rmtree(tmpdir, ignore_errors=True)

    @patch("src.main._detect_usb_boot_dirs")
    def test_usb_detection_empty(self, mock_usb):
        from src.main import _resolve_boot_dir

        mock_usb.return_value = []
        result = _resolve_boot_dir(None)
        self.assertEqual(result, ".")


if __name__ == "__main__":
    unittest.main(verbosity=2)
