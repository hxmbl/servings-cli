"""Path containment checks shared by every file-serving protocol.

Both TFTP and HTTP serve files out of a boot directory, and both used to
carry their own copy of the "is this inside the jail?" check. Those copies
had already drifted apart:

* HTTP compared ``str(Path)`` values against a hard-coded ``"/"`` separator,
  so on Windows (``D:\\boot`` vs ``"D:\\boot/"``) it refused *every* request.
* TFTP had no check at all and happily streamed through a symlink that
  pointed outside the boot directory.

Keep exactly one implementation and use it from both, so they cannot drift
again. Resolution (not string prefix matching) is what makes this correct on
every platform: symlinks, ``..`` and Windows drive/UNC prefixes are all
normalised away before the comparison happens.
"""

import os
from pathlib import Path


def resolve_within(root: Path, candidate: Path) -> Path | None:
    """Resolve ``candidate`` and return it only if it stays inside ``root``.

    Returns None when the path escapes ``root`` (``..``, a symlink, a
    different Windows drive) or cannot be resolved at all. ``root`` itself
    counts as contained, so callers can distinguish "the directory" from
    "outside" without a second comparison.

    Both sides are resolved here, which matters because the root and the
    candidate may reach us by different spellings of the same path (e.g.
    macOS ``/var`` vs ``/private/var``).
    """
    try:
        root_resolved = root.resolve()
        resolved = candidate.resolve()
    except (OSError, ValueError, RuntimeError):
        # RuntimeError: older Pythons raise this on a symlink loop.
        # OSError (ELOOP): 3.13+ raises this instead.
        return None
    if resolved == root_resolved or resolved.is_relative_to(root_resolved):
        return resolved
    return None


def is_within(root: Path, candidate: Path) -> bool:
    """Boolean form of :func:`resolve_within`."""
    return resolve_within(root, candidate) is not None


def native_join(root: Path, url_path: str) -> Path:
    """Join a URL path onto ``root`` using the host's separator rules.

    iPXE and other clients always send ``/``-separated paths. On Windows a
    backslash in a request is a separator rather than a filename character,
    so it must be honoured here or ``..\\..`` would be treated as one oddly
    named file instead of an escape attempt. The caller is still expected to
    run the result through :func:`resolve_within`.
    """
    if os.name == "nt":
        url_path = url_path.replace("\\", "/")
    return root.joinpath(*[seg for seg in url_path.split("/") if seg])
