# DriveDroid + servings-cli: USB Boot Server Workflow

## The Idea

One cable, one phone, any PC boots.

Plug the phone into a PC via USB. The phone first presents itself as a USB CD-ROM
with a live Linux ISO. The PC boots into RAM. Once the ISO is loaded, the phone
switches USB modes — from mass storage to RNDIS tethering — and starts servings-cli.
The PC, now running from RAM, uses the phone as a PXE boot server to load OS images
over the network.

No USB sticks. No network setup. No Ethernet cables. Just the phone.

## Deployment Model

- **Phone is standalone.** No ADB, no SSH to a dev machine. Phone is autonomous.
- **User opens Termux, runs `python3 scripts/usb_boot.py`.** That's the trigger.
- **Phone is a multitool.** USB boot server is one of its capabilities.
- **Phone may or may not have WiFi.** Can't rely on it. USB is the only guaranteed link.

## Workflow

```
┌─────────────────────────────────────────────────────────┐
│  STEP 1: Phone → Mass Storage                           │
│                                                         │
│  Phone presents ISO as USB CD-ROM (DriveDroid-style)    │
│  PC BIOS/UEFI boots from it                             │
│  PC loads live Linux into RAM                           │
└──────────────────────┬──────────────────────────────────┘
                       │ ISO ejected / loaded
                       ▼
┌─────────────────────────────────────────────────────────┐
│  STEP 2: Phone → RNDIS Tethering + servings-cli         │
│                                                         │
│  Phone switches USB gadget: mass_storage → rndis        │
│  PC detects new USB Ethernet adapter                    │
│  DHCP assigns 192.168.38.x addresses                    │
│  servings-cli starts: ProxyDHCP + TFTP + HTTP           │
└──────────────────────┬──────────────────────────────────┘
                       │ PC fetches boot files
                       ▼
┌─────────────────────────────────────────────────────────┐
│  STEP 3: PC boots OS from phone                         │
│                                                         │
│  ProxyDHCP tells PC to load iPXE                        │
│  TFTP serves undionly.kpxe / ipxe.efi                   │
│  HTTP serves iPXE menu with ISOs                        │
│  PC loads chosen OS image                               │
└─────────────────────────────────────────────────────────┘
```

## What We Know Works

### USB Gadget Mode Switching
The phone's Qualcomm USB controller (`7000000.dwc3`) supports ConfigFS gadget
configuration. Available functions:

- `mass_storage.0` — USB mass storage (DriveDroid mode)
- `rndis.rndis` / `rndis_bam.rndis` — USB Ethernet (tethering mode)
- `ffs.adb` — ADB (FunctionFS)

Mode switching via Android property system:
```sh
setprop sys.usb.config mass_storage,adb   # Present ISO to PC
setprop sys.usb.config rndis,adb           # Switch to USB tethering
```

### USB Mass Storage
- LUN backing file: `/config/usb_gadget/g1/functions/mass_storage.0/lun.0/file`
- Set `removable=1`, `ro=1` for ISO boot
- PC sees phone as `/dev/sr0` (CD-ROM)
- Tested with `drivedroid.img` (4MB) and Parrot ISO (7.4GB)
- **PC sees it as an actual drive.** Confirmed: `lsblk` shows `sr0` as 2.2G ROM.
- **Switch takes ~2-3 seconds.** `setprop` triggers Android init scripts.

### USB Tethering (RNDIS)
- Phone: `rndis0` interface, `192.168.38.170/24` (dynamic)
- PC: `enp0s20u1`, gets IP via DHCP (`192.168.38.x`)
- Auto-detected by `_detect_android_ip()` in `main.py`
- All three servers work over USB: ProxyDHCP (4011), TFTP (6969), HTTP (8080)
- **IP is not static.** Android picks from `192.168.42.x` or `192.168.38.x` per session.
- **Server startup ~1 second.** Total switch-to-serving: under 5 seconds.

### Switch Script
Python script `scripts/usb_boot.py` on the phone (~80 lines):
```sh
python3 scripts/usb_boot.py                  # Interactive: pick ISO, start flow
python3 scripts/usb_boot.py /path/to/iso.iso # Direct: use specific ISO
```
Also available as `usb-switch.sh` for manual shell-based testing.

## Known Issues

### 1. rndis0 doesn't auto-init after mode switch
After `setprop sys.usb.config rndis,adb`, the `rndis0` interface may not come up
automatically. Requires manual init:
```sh
ip link set rndis0 up
ip addr add 192.168.42.129/24 dev rndis0
```
The Android init scripts (`init.qcom.usb.rc`) handle this for normal tethering,
but the fast switch from mass_storage may bypass them.

**Fix options:**
- Monitor `sys.usb.state` property, trigger rndis init when it changes
- Write a ueventd listener for `rndis0` appearance
- Add a small delay and poll for the interface

### 2. SELinux blocks ConfigFS writes
With SELinux enforcing, direct ConfigFS writes fail. `setprop` works because
Android's init scripts run in the right SELinux context. For manual operations:
```sh
su -c setenforce 0   # Temporarily permissive
```
Production solution: Magisk policy patch or a dedicated SELinux domain.

### 3. PATH issues under su
`nohup python3` fails because `su -c` doesn't inherit Termux's PATH.
Use full path: `/data/data/com.termux/files/usr/bin/python3`

### 4. ISO must load into RAM
The PC can only use the phone as USB storage OR as network server, not both.
The live Linux ISO must load entirely into RAM before the phone switches modes.
Good candidates: Puppy Linux, Tiny Core, Porteus, custom initramfs.

### 5. DriveDroid is abandoned
Last updated 2018. Modern alternatives:
- **ISOdroid** (active, Kotlin, needs root + custom kernel)
- **UsbMassStorage** (active, Kotlin + Rust, Android 12+)
- **GadgetDrive** (active, ConfigFS-based, Android 5+)

We don't need any of these — we implement the same ConfigFS trick directly.

### 6. USB tethering is unreliable
Different Android versions handle RNDIS differently. The PC's USB driver stack
may not re-initialize properly after a mode switch. Some PCs won't detect the
new device. This is the biggest uncertainty in the whole flow.

### 7. Server got killed during testing
During USB mode switch testing, the servings-cli process was killed. This
happened because `setprop sys.usb.config rndis,adb` triggers Android init
scripts that may restart networking daemons. The server needs to be started
AFTER the switch completes and rndis0 is up, not before.

### 8. USB-only constraint
In real deployment, the phone has no WiFi, no ADB connection, no SSH. The
USB cable to the PC is the ONLY link. After the mode switch, the phone
must be self-contained — it can't call home, can't get help, can't be
debugged remotely. The script must handle all failures gracefully and
report status via Termux output (user is watching the terminal).

## What's Needed to Finish

### Phase 1: `scripts/usb_boot.py` (~80 lines Python)
- [ ] Detect ISOs on `/storage/emulated/0/Disk Images/`
- [ ] Present chosen ISO via `setprop sys.usb.config mass_storage,adb`
- [ ] Set LUN backing file, `removable=1`, `ro=1`
- [ ] Wait for PC to read (timeout / notification / I/O stats)
- [ ] Switch to rndis: `setprop sys.usb.config rndis,adb`
- [ ] Bring up rndis0: `ip link set rndis0 up`
- [ ] Detect phone IP from rndis0
- [ ] Start servings-cli: `python3 -m src.main serve --no-root --android`
- [ ] Log progress to `usb-switch.log`

### Phase 2: Reliable USB switching
- [ ] Fix rndis0 auto-init after mode switch
- [ ] Add ueventd or property trigger for rndis0
- [ ] Test with multiple phone models if possible
- [ ] Handle timing: how long to wait before switching

### Phase 3: ISO loading detection
- [ ] Option A: Timeout (simplest, ~5s for small iPXE ISO)
- [ ] Option B: Poll UDC I/O stats at `/sys/class/udc/7000000.dwc3/`
- [ ] Option C: Termux notification — user taps "PC loaded?" to confirm
- [ ] Option D: Custom iPXE that signals back via HTTP (fully automated)

### Phase 4: Custom iPXE ISO
- [ ] Build small iPXE (~3MB) that loads into RAM fast
- [ ] iPXE script chains to `http://<phone_ip>/boot.cfg`
- [ ] Modify existing `ipxe.iso` on Ventoy to force-load into RAM
- [ ] Or build from scratch with `make bin/ipxe.iso`

## Tests to Run (When on Power)

### Test 1: Cold boot from phone mass storage
**Goal:** Verify PC BIOS/UEFI actually offers the phone as a boot device.
- Switch phone to mass_storage with a known ISO
- Reboot PC, enter BIOS, check boot menu
- Does `sr0` appear as a bootable device?
- Does the PC actually boot from it?
**Status:** UNTESTED. We only tested from a running Linux, not cold boot.

### Test 2: rndis0 reliability after mode switch
**Goal:** Does rndis0 always come up after `setprop sys.usb.config rndis,adb`?
- Switch mass_storage → rndis
- Check if rndis0 exists and has an IP
- Repeat 10 times, count successes
**Status:** UNTESTED. First attempt: rndis0 did NOT auto-init. Manual `ip link set` was needed.

### Test 3: USB tethering IP stability
**Goal:** Is the phone's IP predictable across mode switches?
- Switch to rndis, record IP
- Switch to mass_storage, back to rndis
- Does the IP change?
**Status:** UNTESTED. First test: `192.168.38.170`. Need to test if it's consistent.

### Test 4: UDC I/O stats for read detection
**Goal:** Can we detect when the PC has finished reading the ISO?
- Present ISO via mass_storage
- Poll `/sys/class/udc/7000000.dwc3/` for bytes transferred
- Compare to ISO size
**Status:** UNTESTED. Need to check if the sysfs path exposes transfer stats.

### Test 5: Server survives mode switch
**Goal:** Does servings-cli keep running (or restart cleanly) after USB switch?
- Start server on rndis
- Switch to mass_storage, back to rndis
- Is the server still listening?
**Status:** FAILED. Server was killed during testing. Need to start it AFTER switch.

### Test 6: iPXE ISO load time
**Goal:** How fast does a small iPXE ISO load over USB 2.0 mass storage?
- Present 3MB iPXE ISO
- Time how long until the PC finishes reading
**Status:** UNTESTED. Estimated <1 second for 3MB at USB 2.0 speeds.

### Test 7: Full automated flow
**Goal:** End-to-end: phone presents ISO → PC boots → phone switches → PC gets IP → PC gets boot menu
- Run `usb_boot.py` on phone
- PC cold boots from phone
- Verify PC gets IP and can reach `http://<phone_ip>/boot.cfg`
**Status:** UNTESTED. Depends on Tests 1-6.

## Files

- `scripts/usb_boot.py` — Python script for USB boot workflow (~80 lines)
- `usb-switch.sh` — Shell version for manual testing (on phone)
- `src/main.py:_detect_android_ip()` — Auto-detects USB tethering IP
- `src/server.py` — Starts ProxyDHCP + TFTP + HTTP
- `DRIVEDROID-CONCEPT.md` — This file

## References

- Linux USB Gadget ConfigFS: `Documentation/usb/gadget_configfs.rst`
- Android USB init: `/system/etc/init/hw/init.usb.configfs.rc`
- Qualcomm USB: `/vendor/etc/init/hw/init.qcom.usb.rc`
- UDC: `7000000.dwc3` (Qualcomm DWC3 USB controller)
- Termux boot autostart: `termux-setup-boot`
