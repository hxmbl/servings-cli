# servings-cli

Portable PXE/Boot server — runs on any OS with Python 3.12+.

Serves four protocols to chainload any x86_64 machine over a local network:

1. **DHCP** (UDP 67) — assigns IP addresses and directs PXE clients to your server (root mode)
2. **ProxyDHCP** (UDP 4011) — adds PXE options alongside an existing DHCP server (non-root mode)
3. **TFTP** (UDP 69/6969) — serves the initial bootstrap loader (`undionly.kpxe` / `ipxe.efi`)
4. **HTTP** (TCP 8080) — streams kernels, initrds, and disk images at full link speed

An iPXE `boot.cfg` menu is auto-generated from whatever images and kernels you drop in the boot directory.

---

## Install

```bash
git clone <repo>
cd servings-cli
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
- Auto-detects the USB tethering interface IP (`rndis0`, `usb0`, then `eth0`)
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
- The bootloader(s) this mode advertises must exist in the boot dir **and** be in the TFTP allowlist — with the exact `curl` command to fetch them if missing
- DHCP/TFTP/HTTP ports must be free
- `boot.cfg` must be writable (every client fetches it over HTTP)
- Root mode probes for an existing DHCP server and warns about the conflict

In non-root mode `--boot-file` is ignored: ProxyDHCP picks `undionly.kpxe` or
`ipxe.efi` from the client's PXE architecture string. `undionly.kpxe` is
therefore required and `ipxe.efi` is checked with a warning, so a missing
EFI loader is visible before a UEFI client stalls at TFTP.

Fatal problems stop startup with a clear fix message; `--force` overrides.
Config checks and `boot.cfg` generation run *before* any existing instance is
killed, so a typo'd `--server-ip` can no longer take down a server that was
working. Port availability is checked after the takeover, since the old
instance still owns those ports until then.

If a listener dies while running, it is reported once and the whole server
shuts down with a non-zero exit — staying alive and serving a partial PXE chain
looks exactly like "the client is broken".

While running, each client gets one correlated progress line across protocols:

```
[aa:bb:cc:dd:ee:ff] DHCP ACK 192.168.42.100 → TFTP undionly.kpxe → HTTP GET /boot.cfg
```

Where the chain stops tells you what's wrong: nothing after DHCP = network issue,
nothing after TFTP = missing bootloader, nothing after HTTP = broken boot.cfg.
Non-root mode keys the chain on the IP, since ProxyDHCP never learns the
mac↔ip pairing that root mode's DHCP server does.

A stage is only recorded once its packet has actually been sent, so the chain
never claims a step succeeded when the reply failed on the wire. Where both a MAC
and an IP are known they are tracked as one chain, and evicted together.

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
2. With `--android`: `/sdcard/DiskImages/` and `/storage/emulated/0/DiskImages/`
3. `~/servings-boot/`
4. `~/tftp/`
5. `/srv/tftp/`
6. `/var/lib/tftpboot/`
7. USB drives — scans `/mnt/*`, `/media/*`, and `/run/media/*` for mounted removable drives containing `.iso`/`.img` files or Ventoy markers (POSIX mount points, so nothing is detected on Windows)

There is **no current-working-directory fallback** — serving whatever
directory you happen to be standing in to the whole LAN is not an acceptable
default. If nothing matches, startup fails with a message.

With `--android` the shared-storage paths are checked *first*: the flag is an
explicit request for that layout, and Termux's `$HOME` often has a
`servings-boot/` left over from an earlier run that would otherwise win.

### What goes in it

- `.iso` / `.img` disk images — booted directly via `sanboot`
- `vmlinuz-*` + `initramfs-*.img` pairs — kernel + initrd direct boot
- Standalone `vmlinuz-*` kernels — booted directly without initrd
- PXE bootstrap loaders (served via TFTP): `undionly.kpxe`, `ipxe.efi`, `snponly.efi`, `snp.efi`, `ipxe.efi.signed`, `bootx64.efi`, `grubx64.efi` (download from https://boot.ipxe.org)

Kernels and initrds are paired **by name**: `vmlinuz-6.1` pairs with
`initramfs-6.1.img`. A file counts as an initrd only if it looks like one
(`initrd`/`initramfs` in the name, or an `.initrd` extension) — a bare `.img` is
a disk image, since both spellings are in real use. Anything left unpaired is
reported on startup rather than being glued onto an unrelated kernel, which
would panic at boot. With exactly one kernel and one initrd left over the
pairing is unambiguous, so it is made anyway — with a note saying it was a
guess.

Symlinks that resolve outside the boot directory are skipped with a warning:
they would be listed in the menu but always return 403 over HTTP.

The server regenerates `boot.cfg` (an iPXE menu script) on every start, so it
always reflects what is on disk — there is nothing to delete to force a rescan.

---

## Security

- **HTTP path traversal prevention**: requests like `/../../../etc/passwd` are rejected with 403. Only files inside the boot directory (and configured `extra_paths`) are served. Files are opened once and verified by inode before streaming, closing symlink-swap races. The check compares resolved `Path` objects rather than strings, so it behaves identically on POSIX and Windows.
- **TFTP symlink containment**: the boot-file allowlist forces a bare filename, but that filename can still be a symlink. TFTP resolves and re-checks it against the boot directory, so it will not stream a file that lives outside it.
- **iPXE script injection prevention**: filenames are embedded into `boot.cfg`, so files whose names contain script-dangerous characters (`$`, newlines, `;`, backticks, quotes, etc.) are skipped with a warning — a malicious filename can no longer inject iPXE commands that execute on booting clients.
- **TFTP filename allowlist**: the TFTP server only serves the seven bootstrap loaders listed above (`undionly.kpxe`, `ipxe.efi`, `snponly.efi`, `snp.efi`, `ipxe.efi.signed`, `bootx64.efi`, `grubx64.efi`) — never kernels or ISOs, which are fetched over HTTP instead. Requests for anything else are rejected with "Access denied".
- **TFTP non-ASCII rejection**: filenames containing non-ASCII characters are rejected to prevent encoding issues.
- **TFTP flood tolerance**: RRQs are rate-limited to 20/second per source before any disk read, and stale or forged ACKs are ignored without tearing down in-flight transfers.
- **No silent CWD fallback**: if no boot directory is found, the server refuses to start instead of serving your current directory over HTTP.
- **Careful process cleanup**: startup only kills processes that are verifiably servings-cli servers (a python/launcher first token, then `main.py`/`src.main`/`servings-cli`, then `serve` as its own token), never unrelated processes whose command line merely contains matching text.
- **CLI validation**: `--server-ip` must be a real IPv4 address and `--boot-file` must fit DHCP option 67; invalid values are rejected at startup instead of crashing the DHCP thread mid-request.
- **Failed sends never kill a listener**: if a reply cannot be delivered (route withdrawn, interface down, broadcast refused), the error is logged and the listener keeps serving.
- **Address recycling is announced**: when the DHCP pool wraps and must reuse an address that a live client still holds, that is printed. Eviction does not prevent an address conflict, it creates one — the previous holder is never told — so it must be visible. There is no lease expiry by design (leases last until the process exits), which suits temporary sessions; the pool holds 101 addresses (`.100`–`.200`), so recycling needs ~101 distinct clients in one run.
- **`usb_boot.py` checks `su`'s exit status**: an unrooted device, a denied `su`, or SELinux blocking ConfigFS writes now aborts the workflow with the reason logged, instead of continuing to report "ISO presented" when nothing was presented.

Note: like every PXE server, the UDP listeners bind wildcard addresses — PXE clients may broadcast or arrive on any interface, so these services are LAN-facing by design. Don't expose them to untrusted networks.

---

## How it works

1. Client machine PXE-boots and broadcasts a DHCP discover with option 60 (PXEClient).
2. **Root mode**: servings-cli assigns an IP and responds with PXE boot options.
   **Non-root mode**: your router assigns the IP, then servings-cli responds to the
   PXE-specific request on port 4011.
3. The client loads the bootstrap (`undionly.kpxe` / `ipxe.efi`) via TFTP.
4. iPXE takes over in the client's RAM and requests `boot.cfg` over HTTP.
5. The auto-generated menu lists every image and kernel/initrd pair found in the boot dir.
6. User picks an entry; iPXE either `sanboot`s the disk image directly or loads the kernel+initrd.

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

### Windows (best-effort — untested)
```powershell
# Run PowerShell as Administrator, then:
servings-cli serve --server-ip 192.168.137.1
```
Windows USB tethering typically uses `192.168.137.1`.

Caveats, stated plainly: this platform is **not actively tested**. Path handling
is platform-neutral, but `servings-cli kill` cannot discover processes on
Windows, so stop a previous instance by hand if a port is reported busy. Root
mode binds 67/69 and needs an Administrator shell; the privilege check warns you
if you forgot.

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

`test_wire.py` additionally needs `tshark` on `PATH`; it dissects real traffic
on loopback to check the packets are spec-compliant.

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
                       Root mode only. With --no-root the loader is chosen per
                       client from its PXE architecture instead, so
                       undionly.kpxe and ipxe.efi are what you need on disk.
  --android            Android/Termux mode: scan shared storage, auto-detect USB IP
  --android            Android/Termux mode: scan shared storage, auto-detect USB IP
  --force              Start even if pre-flight checks fail
  --help               Show this message and exit

servings-cli kill

  Kill any running servings-cli server processes.
  (POSIX only — Windows has no equivalent discovery implemented.)
```

---

## License

No.
