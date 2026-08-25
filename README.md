# servings-cli

Portable PXE/Boot server — runs on any OS with Python 3.12+.

Serves three protocols to chainload any x86_64 machine over a local network:

1. **DHCP** (UDP 67) — assigns IP addresses and directs PXE clients to your server (root mode)
2. **ProxyDHCP** (UDP 4011) — adds PXE options alongside an existing DHCP server (non-root mode)
3. **TFTP** (UDP 69/6969) — serves the initial bootstrap loader (`undionly.kpxe` / `ipxe.efi`)
4. **HTTP** (TCP 8080) — streams kernels, initrd, squashfs, and ISO files at full link speed

An iPXE `boot.cfg` menu is auto-generated from whatever ISOs and kernels you drop in the boot directory.

---

## Install

```bash
git clone <repo>
cd servings-termux
pip install -e .
```

Requires Python 3.12+.

---

## Quick start

```bash
# Root mode (default) — full DHCP + PXE, needs sudo:
sudo servings-cli serve --server-ip 192.168.1.100

# Non-root mode — ProxyDHCP alongside your router's DHCP:
servings-cli serve --no-root

# Android/Termux with USB tethering:
servings-cli serve --android
```

---

## Usage

### Root mode (default)

Full DHCP server. Replaces your network's existing DHCP server entirely,
handling both IP address assignment and PXE boot advertisement. Gives the
most seamless PXE experience — the client machine auto-discovers the boot
server without any manual configuration.

```bash
sudo servings-cli serve --server-ip 192.168.1.100
```

Ports: DHCP on 67, TFTP on 69, HTTP on 8080.

### Non-root mode

ProxyDHCP works alongside your existing DHCP server (e.g. your home router).
Your router assigns IP addresses, and servings-cli adds the PXE boot options
that tell the client where to find the bootloader.

```bash
servings-cli serve --no-root
```

Ports: ProxyDHCP on 4011, TFTP on 6969, HTTP on 8080.

### Android / Termux

The `--android` flag adds Termux-specific conveniences on top of whatever
mode you're running in:

- Scans `/sdcard/DiskImages` and `/storage/emulated/0/DiskImages` for boot files
- Auto-detects the USB tethering interface IP (rndis0/usb0)
- Shows platform info in the server banner

```bash
# Non-root on Termux (no root needed):
servings-cli serve --android --no-root

# Root mode on Termux (kill dnsmasq first):
su -c killall dnsmasq
servings-cli serve --android

# Set up shared storage for boot files:
termux-setup-storage
mkdir -p /sdcard/DiskImages
cp archlinux-*.iso /sdcard/DiskImages/
curl -o /sdcard/DiskImages/undionly.kpxe https://boot.ipxe.org/undionly.kpxe
```

## Pre-flight checks & live boot chain

On every start, servings-cli validates its own config instead of failing silently later:

- `--server-ip` must be assigned to a local interface (clients fetch boot files from it directly)
- `--boot-file` must exist in the boot dir **and** be in the TFTP allowlist — with the exact `curl` command to fetch it if missing
- DHCP/TFTP/HTTP ports must be free
- Root mode probes for an existing DHCP server and warns about the conflict

Fatal problems stop startup with a clear fix message; `--force` overrides.

While running, each client gets one correlated progress line across protocols:

```
[aa:bb:cc:dd:ee:ff] DHCP ACK 192.168.42.100 → TFTP undionly.kpxe → HTTP GET /boot.cfg
```

Where the chain stops tells you what's wrong: nothing after DHCP = network issue, nothing after TFTP = missing bootloader, nothing after HTTP = broken boot.cfg.

---

## Port reference

| Mode | DHCP | TFTP | HTTP | Privileges |
|------|------|------|------|------------|
| **Root** (default) | Full DHCP on 67 | 69 | 8080 | sudo/admin |
| **Non-root** (`--no-root`) | ProxyDHCP on 4011 | 6969 | 8080 | None |

---

## Boot directory

The server looks for boot files in these locations (in order):

1. `--boot-dir PATH` if explicitly provided
2. `~/servings-boot/`
3. `~/tftp/`
4. `/srv/tftp/`
5. `/var/lib/tftpboot/`
6. USB drives — scans `/mnt/*`, `/media/*`, and `/run/media/*` for mounted removable drives containing `.iso` files or Ventoy markers
7. Current working directory (fallback)
8. With `--android`: `/sdcard/DiskImages/` and `/storage/emulated/0/DiskImages/`

### What goes in it

- `.iso` / `.img` files — booted directly via `sanboot`
- `vmlinuz-*` + `initramfs-*.img` pairs — kernel + initrd direct boot
- Standalone `vmlinuz-*` kernels — booted directly without initrd
- PXE bootstrap loaders (served via TFTP): `undionly.kpxe`, `ipxe.efi`, `snponly.efi`, `snp.efi`, `ipxe.efi.signed`, `bootx64.efi`, `grubx64.efi` (download from https://boot.ipxe.org)

The server generates `boot.cfg` (an iPXE menu script) on every start. Delete it to force a fresh scan.

---

## Security

- **HTTP path traversal prevention**: requests like `/../../../etc/passwd` are rejected with 403. Only files inside the boot directory (and configured `extra_paths`) are served. Files are opened once and verified by inode before streaming, closing symlink-swap races.
- **iPXE script injection prevention**: filenames are embedded into `boot.cfg`, so files whose names contain script-dangerous characters (`$`, newlines, `;`, backticks, quotes, etc.) are skipped with a warning — a malicious filename can no longer inject iPXE commands that execute on booting clients.
- **TFTP filename allowlist**: the TFTP server only serves files in its allowlist (`undionly.kpxe`, `ipxe.efi`, `snponly.efi`, `snp.efi`, `ipxe.efi.signed`, `bootx64.efi`, `grubx64.efi`). Requests for other files are rejected with "Access denied".
- **TFTP non-ASCII rejection**: filenames containing non-ASCII characters are rejected to prevent encoding issues.
- **TFTP flood tolerance**: RRQs are rate-limited per source, and stale/forged ACKs no longer tear down in-flight transfers.
- **No silent CWD fallback**: if no boot directory is found, the server refuses to start instead of serving your current directory over HTTP.
- **Careful process cleanup**: startup only kills processes that are verifiably servings-cli servers (python/servings-cli launcher + `serve` subcommand), never unrelated processes whose command line merely contains matching text.
- **CLI validation**: `--server-ip` must be a real IPv4 address and `--boot-file` must fit DHCP option 67; invalid values are rejected at startup instead of crashing the DHCP thread mid-request.

Note: like every PXE server, the UDP listeners bind wildcard addresses — PXE clients may broadcast or arrive on any interface, so these services are LAN-facing by design. Don't expose them to untrusted networks.

---

## How it works

1. Client machine PXE-boots and broadcasts a DHCP discover with option 60 (PXEClient).
2. **Root mode**: servings-cli assigns an IP and responds with PXE boot options.
   **Non-root mode**: your router assigns the IP, then servings-cli responds to the
   PXE-specific request on port 4011.
3. The client loads the bootstrap (`undionly.kpxe` / `ipxe.efi`) via TFTP.
4. iPXE takes over in the client's RAM and requests `boot.cfg` over HTTP.
5. The auto-generated menu lists every ISO and kernel+initrd pair found in the boot dir.
6. User picks an entry; iPXE either `sanboot`s the ISO directly or loads the kernel+initrd.

---

## Platform notes

### Linux
```bash
sudo servings-cli serve --server-ip 192.168.1.100
```
Root mode works with `sudo`. Ports < 1024 require root privileges.
Without root, use `--no-root`.

### macOS
```bash
sudo servings-cli serve --server-ip 192.168.2.1
```
Same as Linux — `sudo` for root mode, `--no-root` otherwise.
USB tethering on macOS typically uses `192.168.2.1` (check System Settings → Sharing).

### Windows
```bash
# Run as Administrator, then:
servings-cli serve --server-ip 192.168.137.1
```
Run PowerShell or Command Prompt as Administrator for root mode.
Windows USB tethering typically uses `192.168.137.1`.

### Android (Termux)
```bash
servings-cli serve --android
```
Non-root works on any device. Root mode requires a rooted device.

---

## Tests

```bash
python3 -m pytest test/ -v
```

---

## CLI reference

```
servings-cli serve [OPTIONS]

Options:
  --port INTEGER       DHCP/ProxyDHCP UDP port (only used with --no-root) [default: 4011]
  --tftp-port INTEGER  TFTP UDP port (only used with --no-root) [default: 6969]
  --http-port INTEGER  HTTP TCP port for iPXE payloads [default: 8080]
  --boot-dir TEXT      Directory containing boot files (default: auto-detect)
  --no-root            Non-root mode: ProxyDHCP on 4011 + TFTP on 6969
  --server-ip TEXT     Server IP on the client network (default: 192.168.42.129)
  --boot-file TEXT     Boot file to serve [default: undionly.kpxe]
  --android            Android/Termux mode: scan shared storage, auto-detect USB IP
  --force              Start even if pre-flight checks fail
  --help               Show this message and exit

servings-cli kill

  Kill any running servings-cli server processes.
```

---

## License

No.
