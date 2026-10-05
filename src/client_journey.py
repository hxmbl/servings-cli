"""Per-client PXE boot-chain tracking — correlated progress across protocols.

DHCP sees MACs, TFTP sees IPs, HTTP sees IPs. In root mode the DHCP server
knows the mac↔ip pairing, so this module links those identities and the console
shows one growing chain per physical machine instead of scattered per-protocol
log lines:

    [aa:bb:cc:dd:ee:ff] DHCP ACK 192.168.42.100 → TFTP undionly.kpxe → HTTP GET /boot.cfg

That answers "where did this client stop?" at a glance: nothing after DHCP
means wrong network config; nothing after TFTP means a missing bootloader;
nothing after HTTP means a broken boot.cfg.

In non-root mode nothing observes the pairing — ProxyDHCP sees the MAC but the
IP comes from the existing router — so chains are keyed on the IP alone and
carry no MAC label.
"""

import threading
from collections import OrderedDict

_lock = threading.Lock()
# key (MAC or IP) -> shared OrderedDict {stage: latest detail}.
# Linked identities point at the SAME dict, so updates via any alias show up
# in every alias's chain. Both keys of a group are always evicted together.
_journeys: dict[str, OrderedDict] = {}
# Distinct clients tracked. A root-mode client occupies two keys (MAC + IP),
# so this is roughly 128 machines before the oldest is dropped.
MAX_JOURNEYS = 256


def reset() -> None:
    """Clear all tracked journeys (used between tests)."""
    with _lock:
        _journeys.clear()


def _evict_if_needed_locked() -> None:
    """Drop the oldest journey(s) to stay under MAX_JOURNEYS.

    Evicts *whole alias groups*. A MAC and its IP point at the same dict, so
    deleting just one key leaves the other pointing at a journey that can no
    longer find its MAC — and the next event on that key creates a second,
    disconnected dict. One machine then renders as two unrelated chains, which
    is precisely the confusion this module exists to prevent.
    """
    while len(_journeys) >= MAX_JOURNEYS:
        oldest_key = next(iter(_journeys))
        oldest_journey = _journeys[oldest_key]
        # Remove every alias pointing at the same journey.
        for key in [k for k, v in _journeys.items() if v is oldest_journey]:
            del _journeys[key]


def link_ip_to_mac(ip: str, mac_str: str) -> None:
    """Alias an IP to a MAC so both keys render the same journey.

    If either key already pointed at a *different* journey, that stale journey
    is discarded rather than left dangling under the other alias. The DHCP
    address pool recycles addresses, so this happens for real: without it the
    recycled IP would keep rendering the previous machine's boot chain under
    the new machine's MAC label.
    """
    with _lock:
        _evict_if_needed_locked()
        mac_journey = _journeys.get(mac_str)
        ip_journey = _journeys.get(ip)
        if mac_journey is None or ip_journey is None:
            # One side is new (or they were never linked): start a fresh
            # journey rather than merging two unrelated chains.
            mac_journey = OrderedDict()
            _journeys[mac_str] = mac_journey
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
