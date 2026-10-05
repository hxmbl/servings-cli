"""iPXE boot config generator — scans a directory and auto-generates boot.cfg.

boot.cfg is an iPXE script presenting a menu of the images and kernels found in
the boot directory. iPXE fetches it over HTTP (port 8080) after the TFTP stage.

Two rules keep it correct rather than merely working:

* Embedded paths are POSIX-style and screened for iPXE metacharacters, since a
  filename on disk becomes a line of a script every booting client executes.
* Only files the HTTP server will actually serve are listed. Anything else
  (escaping symlink, unsafe name) is skipped *with a warning* — a silent drop
  looks identical to "you have no boot files", which is the failure this whole
  generator exists to prevent.
"""

from pathlib import Path

from src import pathguard

# Characters allowed in relative paths embedded in boot.cfg. Anything else
# (control chars, $ ` ' " ; & | < > \ # % { } : etc.) could let a crafted
# FILENAME inject iPXE commands or ${settings} expansion into the script that
# every PXE client executes. Files with such names are skipped with a warning.
_UNSAFE_FILENAME_CHARS = frozenset(
    "$`'\";&|<>\\#%{}[]*?!~^:=,+@\x00\x0b\x0c\x1c\x1d\x1e\x1f\x7f"
)


def _is_safe_boot_path(rel_path: str) -> bool:
    """True if a relative path can be safely embedded in an iPXE script."""
    return not any(ch in _UNSAFE_FILENAME_CHARS or ord(ch) < 0x20 for ch in rel_path)


_RESERVED_KEYS = frozenset({"menu", "boot_none", "failed"})


def _make_safe_key(rel_path: str, used: set[str]) -> str:
    """Build a unique, injection-proof goto label for a boot entry."""
    base = "".join(
        ch if (ch.isascii() and ch.isalnum()) or ch == "-" else "_"
        for ch in rel_path.replace(" ", "_").replace(".", "_").replace("/", "_")
    ).strip("_-")
    if not base:
        base = "entry"
    key = base
    n = 2
    while key in used:
        key = f"{base}_{n}"
        n += 1
    used.add(key)
    return key


# ".img" is deliberately NOT here: both a raw disk image and an initramfs can
# legitimately be named *.img, and treating every one of them as an initrd made
# unpaired disk images vanish from the menu. A file is an initrd if it *looks*
# like one — see _is_initrd and classify.
_INITRD_EXTENSIONS = frozenset({".initrd"})
_DISK_IMAGE_EXTENSIONS = frozenset({".iso", ".img"})
# Every suffix that is part of a boot filename rather than part of its version.
_KERNEL_EXTENSIONS = frozenset({".kernel", ".vmlinuz", ".bzimage"})
_BOOT_EXTENSIONS = _KERNEL_EXTENSIONS | _INITRD_EXTENSIONS | _DISK_IMAGE_EXTENSIONS
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
    """Check if a file looks like an initrd/initramfs.

    Name-based on purpose: an `initramfs-*.img` is an initrd even though
    `.img` is also the disk-image extension. See _INITRD_EXTENSIONS.
    """
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


def _is_disk_image(path: Path) -> bool:
    """Check if a file is a bootable disk image (sanboot target)."""
    return path.suffix.lower() in _DISK_IMAGE_EXTENSIONS


def _strip_boot_ext(name: str) -> str:
    """Strip a *known* boot extension, leaving dotted version numbers intact.

    Path.stem is the wrong tool here: Path("vmlinuz-6.1").stem == "vmlinuz-6"
    because Python reads ".1" as a suffix, while Path("initramfs-6.1.img").stem
    == "initramfs-6.1". The two could therefore never compare equal, so
    vmlinuz-<ver> + initramfs-<ver> pairs only ever appeared via the
    guess-the-fallback path rather than by actually matching.
    """
    lowered = name.lower()
    for ext in sorted(_BOOT_EXTENSIONS, key=len, reverse=True):
        if lowered.endswith(ext) and len(name) > len(ext):
            return name[: -len(ext)]
    return name


def classify(path: Path) -> str:
    """Classify one file as 'initrd', 'kernel' or 'disk_image'.

    A single ordered decision replaces the old four-pass scheme. The passes
    disagreed about priority: the initrd pass ran before the image pass, so
    `arch.iso` was fine but any `.img` was claimed as an initrd no matter
    what it was, and the later "unclaimed images" pass could therefore never
    fire. Order here matters only for genuinely ambiguous names, and it puts
    the more specific "looks like an initrd" judgement ahead of the generic
    ".img means disk image" one.

    Returns "" for anything that isn't bootable.
    """
    if _is_initrd(path):
        return "initrd"
    if _is_kernel(path):
        return "kernel"
    if _is_disk_image(path):
        return "disk_image"
    return ""


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
        - .iso / .img images    -> booted via sanboot (direct disk boot)
        - vmlinuz + initrd     -> booted via kernel/initrd direct boot
        - standalone kernels   -> booted via kernel-only direct boot

    Writes boot.cfg to boot_dir and returns its path.
    """
    image_files: list[str] = []
    kernel_initrd_pairs: list[tuple[str, str]] = []
    standalone_kernels: list[str] = []

    # Every candidate file under boot_dir, keyed by lowercased relative path.
    # Case-folding is deliberate: on a case-insensitive filesystem (macOS,
    # Windows) Arch.iso and arch.iso are one file, and listing both would
    # produce two menu entries that resolve to the same bytes.
    all_files: dict[str, tuple[Path, str]] = {}
    for f in sorted(boot_dir.rglob("*")):
        rel = f.relative_to(boot_dir)
        # Skip venv/pycache dirs and macOS/Windows system junk
        if any(part in _IGNORED_DIRS for part in rel.parts):
            continue
        # Hidden files, and macOS resource forks (._prefix)
        if f.name.startswith("."):
            continue
        if f.name in _IGNORED_NAMES:
            continue
        if not f.is_file():
            continue
        # as_posix() keeps the embedded path identical on every platform;
        # a native separator would both trip _is_safe_boot_path (backslash is
        # on the unsafe list) and stop matching the URL HTTP is asked for.
        rel_path = rel.as_posix()
        if not _is_safe_boot_path(rel_path):
            print(
                f"[!] boot.cfg: skipping {rel_path!r} — filename contains "
                "characters that are unsafe to embed in an iPXE script"
            )
            continue
        # Only list files the HTTP server will actually serve. A symlink
        # pointing outside the boot dir used to become a permanent menu entry
        # that returned 403 for every client.
        if pathguard.resolve_within(boot_dir, f) is None:
            print(
                f"[!] boot.cfg: skipping {rel_path!r} — resolves outside the "
                f"boot directory and would 403 over HTTP"
            )
            continue
        all_files[rel_path.lower()] = (f, rel_path)

    def _label_from_relpath(rel_path: str) -> str:
        return _label_from_filename(rel_path.rsplit("/", 1)[-1])

    # Collect initrds first, then pair them with kernels. classify() resolves
    # the ordering ambiguity in one place instead of via competing passes.
    initrds: dict[str, str] = {}
    for rel_lower, (path, rel_path) in all_files.items():
        if classify(path) != "initrd":
            continue
        base = _strip_boot_ext(path.name).lower()
        for prefix in ("initramfs-", "initrd-"):
            if base.startswith(prefix):
                base = base[len(prefix) :]
                break
        for suffix in ("-initrd", "-initramfs", "_initrd", "_initramfs"):
            if base.endswith(suffix):
                base = base[: -len(suffix)]
                break
        initrds[base] = rel_path

    claimed_initrds: set[str] = set()
    for rel_lower, (path, rel_path) in all_files.items():
        kind = classify(path)
        if kind == "disk_image":
            image_files.append(rel_path)
        elif kind == "kernel":
            base = _strip_boot_ext(path.name).lower()
            for prefix in ("vmlinuz-", "bzimage-"):
                if base.startswith(prefix):
                    base = base[len(prefix) :]
                    break

            if base in initrds:
                initrd = initrds[base]
                claimed_initrds.add(initrd)
                kernel_initrd_pairs.append((rel_path, initrd))
            else:
                standalone_kernels.append(rel_path)

    leftovers = [
        rel for rel in initrds.values() if rel not in claimed_initrds
    ]

    # Unambiguous rescue: exactly one kernel and one initrd left over is almost
    # certainly a pair whose names just didn't line up, so take it — but say so,
    # since it is a guess. Guessing with more than one candidate is not safe:
    # the wrong initrd panics the kernel at boot, so ambiguous leftovers are
    # only reported.
    if len(leftovers) == 1 and len(standalone_kernels) == 1:
        kern = standalone_kernels.pop()
        initrd = leftovers[0]
        kernel_initrd_pairs.append((kern, initrd))
        print(
            f"[!] boot.cfg: pairing {kern!r} with {initrd!r} by position — "
            "no name match found. Rename them (vmlinuz-<ver> / initramfs-<ver>) "
            "to make this explicit."
        )
        leftovers = []
    elif leftovers and standalone_kernels:
        print(
            f"[!] boot.cfg: {len(leftovers)} initrd(s) and "
            f"{len(standalone_kernels)} kernel(s) could not be matched by name:"
        )
        for rel in leftovers:
            print(f"      unpaired initrd: {rel}")
        for rel in standalone_kernels:
            print(f"      unpaired kernel: {rel}")

    # An initrd with no kernel is not bootable on its own, and handing it to
    # an unrelated kernel panics at boot. Say so instead of dropping it.
    for rel_path in leftovers:
        print(f"[!] boot.cfg: ignoring unpaired initrd {rel_path!r}")

    # Unique, sanitized goto labels — collisions would corrupt the menu
    used_keys: set[str] = set(_RESERVED_KEYS)
    image_keys = [_make_safe_key(p, used_keys) for p in image_files]
    pair_keys = [_make_safe_key(k, used_keys) for k, _ in kernel_initrd_pairs]
    kern_keys = [_make_safe_key(k, used_keys) for k in standalone_kernels]

    # Build iPXE script
    script = "#!ipxe\n"
    script += "# Auto-generated by servings-cli. Do not edit.\n"
    script += "# Restart the server to regenerate from current disk images.\n\n"
    script += "set timeout 30000\n\n"
    script += ":menu\n"
    script += "menu servings-cli PXE Boot Server\n"

    has_items = bool(image_files or kernel_initrd_pairs or standalone_kernels)

    if image_files:
        script += "item --gap -- Disk Images\n"
        for key, image in zip(image_keys, image_files):
            script += f"item {key}    {_label_from_relpath(image)}\n"

    if kernel_initrd_pairs:
        script += "item --gap -- Kernel + Initrd\n"
        for (kern, initrd), key in zip(kernel_initrd_pairs, pair_keys):
            script += f"item {key}    {_label_from_relpath(kern)}\n"

    if standalone_kernels:
        script += "item --gap -- Kernels\n"
        for kern, key in zip(standalone_kernels, kern_keys):
            script += f"item {key}    {_label_from_relpath(kern)}\n"

    if not has_items:
        script += "item --gap -- No bootable images found\n"
        script += "item --gap -- Place .iso, .vmlinuz, or .kernel files here\n"
        script += "goto boot_none\n"

    script += "\nchoose target || goto boot_none\n\n"

    for key, image in zip(image_keys, image_files):
        script += f":{key}\n"
        script += f"set boot-path /{image}\n"
        script += "sanboot ${boot-path} || goto failed\n\n"

    for (kern, initrd), key in zip(kernel_initrd_pairs, pair_keys):
        script += f":{key}\n"
        script += f"kernel /{kern} || goto failed\n"
        script += f"initrd /{initrd} || goto failed\n"
        script += "boot || goto failed\n\n"

    for kern, key in zip(standalone_kernels, kern_keys):
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
        f"[+] Generated boot.cfg ({len(image_files)} images, "
        f"{len(kernel_initrd_pairs)} pairs, {len(standalone_kernels)} kernels)"
    )
    return cfg_path
