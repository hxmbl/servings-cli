"""iPXE boot config generator — scans a directory and auto-generates boot.cfg.

boot.cfg is an iPXE script that shows a menu of available ISOs and kernels.
iPXE loads this from the HTTP server (port 8080) after the TFTP stage.
"""

from pathlib import Path

_INITRD_EXTENSIONS = frozenset({".initrd", ".img"})
_INITRD_NAMES = frozenset({"initrd", "initramfs"})
_IGNORED_NAMES = frozenset({"boot.cfg", ".DS_Store", "undionly.kpxe", "ipxe.efi"})
_IGNORED_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "__pycache__",
        ".svn",
        ".hg",
        ".Spotlight-V100",
        ".fseventsd",
        ".TemporaryItems",
        ".Trashes",
        ".vol",
        "System Volume Information",
        "$RECYCLE.BIN",
    }
)


def _is_initrd(path: Path) -> bool:
    """Check if a file looks like an initrd/initramfs."""
    ext = path.suffix.lower()
    if ext in _INITRD_EXTENSIONS:
        return True
    name_lower = path.name.lower()
    return any(pattern in name_lower for pattern in _INITRD_NAMES)


def _is_kernel(path: Path) -> bool:
    """Check if a file looks like a bootable kernel."""
    ext = path.suffix.lower()
    if ext in (".kernel", ".vmlinuz", ".bzImage"):
        return True
    name_lower = path.name.lower()
    if name_lower.startswith("vmlinuz") or name_lower.startswith("bzimage"):
        return True
    return False


def _label_from_filename(name: str) -> str:
    """Turn 'arch-linux-2024.01.iso' into 'Arch Linux'."""
    label = name.rsplit(".", 1)[0]
    label = label.replace("-", " ").replace("_", " ")
    words = []
    for w in label.split():
        if len(w) <= 3 and w.isalnum():
            words.append(w.upper())
        else:
            words.append(w.capitalize())
    return " ".join(words)


def generate_boot_config(boot_dir: Path) -> Path:
    """Scan boot_dir recursively for bootable images and write an iPXE menu script.

    Detects three patterns:
        - .iso files           -> booted via sanboot (direct ISO boot)
        - vmlinuz + initrd     -> booted via kernel/initrd direct boot
        - standalone kernels   -> booted via kernel-only direct boot

    Writes boot.cfg to boot_dir and returns its path.
    """
    iso_files: list[str] = []
    kernel_initrd_pairs: list[tuple[str, str]] = []
    standalone_kernels: list[str] = []

    # Collect all relevant files recursively (skip ignored)
    # key: lowercase relative path, value: (full Path, relative path string)
    all_files: dict[str, tuple[Path, str]] = {}
    for f in sorted(boot_dir.rglob("*")):
        rel = f.relative_to(boot_dir)
        # Skip hidden dirs, venv, pycache, macOS/Windows junk
        if any(part in _IGNORED_DIRS for part in rel.parts):
            continue
        # Skip macOS resource forks (._prefix) and .fseventsd/.visync
        if f.name.startswith("._") or f.name.startswith("."):
            continue
        if f.is_file() and f.name not in _IGNORED_NAMES:
            rel_path = str(rel)
            all_files[rel_path.lower()] = (f, rel_path)

    def _label_from_relpath(rel_path: str) -> str:
        return _label_from_filename(Path(rel_path).name)

    # Pass 1: ISOs are unambiguous
    claimed: set[str] = set()
    for rel_lower, (path, rel_path) in all_files.items():
        if path.suffix.lower() == ".iso":
            iso_files.append(rel_path)
            claimed.add(rel_lower)

    # Pass 2: Identify initrds
    initrds: dict[str, str] = {}
    for rel_lower, (path, rel_path) in all_files.items():
        if rel_lower in claimed:
            continue
        if _is_initrd(path):
            base = path.stem.lower()
            for prefix in ("initramfs-", "initrd-"):
                if base.startswith(prefix):
                    base = base[len(prefix) :]
                    break
            for suffix in ("-initrd", "-initramfs", "_initrd", "_initramfs"):
                if base.endswith(suffix):
                    base = base[: -len(suffix)]
                    break
            initrds[base] = rel_path
            claimed.add(rel_lower)

    # Pass 3: Identify kernels and pair with initrds
    for rel_lower, (path, rel_path) in all_files.items():
        if rel_lower in claimed:
            continue
        if _is_kernel(path):
            base = path.stem.lower()
            for prefix in ("vmlinuz-", "bzimage-"):
                if base.startswith(prefix):
                    base = base[len(prefix) :]
                    break

            if base in initrds:
                kernel_initrd_pairs.append((rel_path, initrds.pop(base)))
                claimed.add(rel_lower)
            else:
                standalone_kernels.append(rel_path)
                claimed.add(rel_lower)

    # Remaining unclaimed .img files become standalone
    for rel_lower, (path, rel_path) in all_files.items():
        if rel_lower not in claimed and path.suffix.lower() in (
            ".img",
            ".kernel",
            ".vmlinuz",
            ".bzImage",
        ):
            standalone_kernels.append(rel_path)
            claimed.add(rel_lower)

    # Fallback: pair first unpaired initrd with first standalone kernel
    if initrds and standalone_kernels:
        kern = standalone_kernels.pop(0)
        initrd = next(iter(initrds.values()))
        initrds.clear()
        kernel_initrd_pairs.insert(0, (kern, initrd))

    # Build iPXE script
    script = "#!ipxe\n"
    script += "# Auto-generated by servings-cli. Do not edit.\n"
    script += "# Restart the server to regenerate from current disk images.\n\n"
    script += "set timeout 30000\n\n"
    script += ":menu\n"
    script += "menu servings-cli PXE Boot Server\n"

    has_items = bool(iso_files or kernel_initrd_pairs or standalone_kernels)

    if iso_files:
        script += "item --gap -- Disk Images\n"
        for iso in iso_files:
            key = iso.replace(" ", "_").replace(".", "_").replace("/", "_")
            script += f"item {key}    {_label_from_relpath(iso)}\n"

    if kernel_initrd_pairs:
        script += "item --gap -- Kernel + Initrd\n"
        for kern, initrd in kernel_initrd_pairs:
            key = kern.replace(" ", "_").replace(".", "_").replace("/", "_")
            script += f"item {key}    {_label_from_relpath(kern)}\n"

    if standalone_kernels:
        script += "item --gap -- Kernels\n"
        for kern in standalone_kernels:
            key = kern.replace(" ", "_").replace(".", "_").replace("/", "_")
            script += f"item {key}    {_label_from_relpath(kern)}\n"

    if not has_items:
        script += "item --gap -- No bootable images found\n"
        script += "item --gap -- Place .iso, .vmlinuz, or .kernel files here\n"
        script += "goto boot_none\n"

    script += "\nchoose target || goto boot_none\n\n"

    for iso in iso_files:
        key = iso.replace(" ", "_").replace(".", "_").replace("/", "_")
        script += f":{key}\n"
        script += f"set boot-path /{iso}\n"
        script += "sanboot ${boot-path} || goto failed\n\n"

    for kern, initrd in kernel_initrd_pairs:
        key = kern.replace(" ", "_").replace(".", "_").replace("/", "_")
        script += f":{key}\n"
        script += f"kernel /{kern} || goto failed\n"
        script += f"initrd /{initrd} || goto failed\n"
        script += "boot || goto failed\n\n"

    for kern in standalone_kernels:
        key = kern.replace(" ", "_").replace(".", "_").replace("/", "_")
        script += f":{key}\n"
        script += f"kernel /{kern} || goto failed\n"
        script += "boot || goto failed\n\n"

    script += ":boot_none\n"
    script += "echo No bootable images found.\n"
    script += "echo Place .iso, .vmlinuz, or .kernel files in the boot directory.\n"
    script += "sleep 5\n"
    script += "goto menu\n\n"

    script += ":failed\n"
    script += "echo Boot failed. Returning to menu in 5 seconds...\n"
    script += "sleep 5\n"
    script += "goto menu\n"

    cfg_path = boot_dir / "boot.cfg"
    cfg_path.write_text(script, encoding="utf-8")
    print(
        f"[+] Generated boot.cfg ({len(iso_files)} ISOs, {len(kernel_initrd_pairs)} pairs, {len(standalone_kernels)} kernels)"
    )
    return cfg_path
