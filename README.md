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
mkdir -p /sdcard/Disk\ Images
cp archlinux-*.iso /sdcard/Disk\ Images/
curl -o /sdcard/Disk\ Images/undionly.kpxe https://boot.ipxe.org/undionly.kpxe
```

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
6. Current working directory (fallback)
7. With `--android`: `/sdcard/DiskImages/` and `/storage/emulated/0/DiskImages/`

### What goes in it

- `.iso` files — booted directly via `sanboot`
- `vmlinuz-*` + `initramfs-*.img` pairs — kernel + initrd direct boot
- `undionly.kpxe` / `ipxe.efi` — PXE bootstrap loader (download from https://boot.ipxe.org)

The server generates `boot.cfg` (an iPXE menu script) on every start. Delete it to force a fresh scan.

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
python3 -m unittest discover -s test -v
```

---

## CLI reference

```
servings-cli serve [OPTIONS]

Options:
  --port INTEGER       DHCP/ProxyDHCP UDP port (only used with --no-root)
  --tftp-port INTEGER  TFTP UDP port (only used with --no-root)
  --http-port INTEGER  HTTP TCP port for iPXE payloads
  --boot-dir TEXT      Directory containing boot files (default: auto-detect)
  --no-root            Non-root mode: ProxyDHCP on 4011 + TFTP on 6969
  --server-ip TEXT     Server IP on the client network
  --boot-file TEXT     Boot file to serve
  --android            Android/Termux mode
  --help               Show this message and exit
```

---

## License

No.
