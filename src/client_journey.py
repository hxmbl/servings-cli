"""Per-client PXE boot-chain tracking — correlated progress across protocols.

DHCP sees MACs, TFTP sees IPs, HTTP sees IPs. This module links those
identities (DHCP learns the mac↔ip pair) so the console shows one growing
chain per physical machine instead of scattered per-protocol log lines:

    [aa:bb:cc:dd:ee:ff] DHCP ACK 192.168.42.100 → TFTP undionly.kpxe → HTTP GET /boot.cfg

That answers "where did this client stop?" at a glance: nothing after DHCP
means wrong network config; nothing after TFTP means a missing bootloader;
nothing after HTTP means a broken boot.cfg.
"""

import threading
from collections import OrderedDict

_lock = threading.Lock()
# key (MAC or IP) -> shared OrderedDict {stage: latest detail}.
# Linked identities point at the SAME dict, so updates via any alias show up
# in every alias's chain.
_journeys: dict[str, OrderedDict] = {}
MAX_JOURNEYS = 256


def reset() -> None:
    """Clear all tracked journeys (used between tests)."""
    with _lock:
        _journeys.clear()


def _evict_if_needed_locked() -> None:
    while len(_journeys) >= MAX_JOURNEYS:
        oldest = next(iter(_journeys))
        del _journeys[oldest]


def link_ip_to_mac(ip: str, mac_str: str) -> None:
    """Alias an IP to a MAC so both keys render the same journey."""
    with _lock:
        _evict_if_needed_locked()
        mac_journey = _journeys.setdefault(mac_str, OrderedDict())
        _journeys[ip] = mac_journey


def _mac_alias_locked(journey: OrderedDict) -> str | None:
    for key, value in _journeys.items():
        if value is journey and ":" in key:
            return key
    return None


def record(key: str, stage: str, detail: str) -> None:
    """Record a client event and print its chain so far, labeled by MAC when known."""
    with _lock:
        _evict_if_needed_locked()
        journey = _journeys.setdefault(key, OrderedDict())
        journey[stage] = detail  # re-assignment keeps original position
        label = _mac_alias_locked(journey) or key
        chain = " → ".join(
            f"{stage} {detail}".strip() for stage, detail in journey.items()
        )
        print(f"[{label}] {chain}")


def chain_for(key: str) -> str:
    """Render a client's current chain (without printing). Empty string if unseen."""
    with _lock:
        journey = _journeys.get(key)
        if journey is None:
            return ""
        return " → ".join(
            f"{stage} {detail}".strip() for stage, detail in journey.items()
        )
