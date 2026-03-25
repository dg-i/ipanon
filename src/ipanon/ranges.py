"""IP range classification for anonymization categories.

Category A: Range-preserved (lock prefix, anonymize remaining bits)
Category B: Pass-through (kept unchanged)
Category C: Public (full anonymization, must not land in A or B)
"""

from __future__ import annotations

import ipaddress
from enum import Enum, auto
from typing import List, NamedTuple, Set, Tuple, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]
IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]


class Category(Enum):
    RANGE_PRESERVED = auto()  # Category A
    PASS_THROUGH = auto()  # Category B
    PUBLIC = auto()  # Category C


class RangeEntry(NamedTuple):
    network: IPNetwork
    locked_bits: int  # number of prefix bits to lock (preserve)


# Category A: Range-Preserved (IPv4)
CATEGORY_A_V4: List[RangeEntry] = [
    RangeEntry(ipaddress.IPv4Network("10.0.0.0/8"), 8),
    RangeEntry(ipaddress.IPv4Network("172.16.0.0/12"), 12),
    RangeEntry(ipaddress.IPv4Network("192.168.0.0/16"), 16),
    RangeEntry(ipaddress.IPv4Network("100.64.0.0/10"), 10),
    RangeEntry(ipaddress.IPv4Network("169.254.0.0/16"), 16),
]

# Category A: Range-Preserved (IPv6)
CATEGORY_A_V6: List[RangeEntry] = [
    RangeEntry(ipaddress.IPv6Network("fc00::/7"), 7),
    RangeEntry(ipaddress.IPv6Network("fe80::/10"), 10),
]

# Category B: Pass-Through (IPv4)
CATEGORY_B_V4: List[IPNetwork] = [
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("192.0.0.0/24"),
    ipaddress.IPv4Network("192.0.2.0/24"),
    ipaddress.IPv4Network("198.18.0.0/15"),
    ipaddress.IPv4Network("198.51.100.0/24"),
    ipaddress.IPv4Network("203.0.113.0/24"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
    ipaddress.IPv4Network("255.255.255.255/32"),
]

# Category B: Pass-Through (IPv6)
# Note: 0000::/8 and 0100::/8 are broad ranges that subsume more specific entries
# (::/128, ::1/128, ::ffff:0:0/96, 64:ff9b::/96, 100::/64) but we keep those
# for documentation clarity. Order doesn't matter since all are Cat B.
CATEGORY_B_V6: List[IPNetwork] = [
    ipaddress.IPv6Network("0000::/8"),
    ipaddress.IPv6Network("0100::/8"),
    ipaddress.IPv6Network("::/128"),
    ipaddress.IPv6Network("::1/128"),
    ipaddress.IPv6Network("::ffff:0:0/96"),
    ipaddress.IPv6Network("64:ff9b::/96"),
    ipaddress.IPv6Network("100::/64"),
    ipaddress.IPv6Network("ff00::/8"),
]

# Combined forbidden output ranges for Category C (public) IPs
# A public IP must not anonymize to land in any of these
FORBIDDEN_OUTPUT_V4: List[IPNetwork] = [entry.network for entry in CATEGORY_A_V4] + CATEGORY_B_V4

FORBIDDEN_OUTPUT_V6: List[IPNetwork] = [entry.network for entry in CATEGORY_A_V6] + CATEGORY_B_V6


# --- IPv4 first-octet classification for permutation ---

# Reserved first octets: entirely Cat A or Cat B (no public IPs in these /8 blocks)
# 0 (this-network), 10 (RFC1918), 127 (loopback), 224-255 (multicast + reserved)
RESERVED_FIRST_OCTETS_V4: Set[int] = {0, 10, 127} | set(range(224, 256))

# Mixed first octets: contain both reserved sub-ranges and public IPs
MIXED_FIRST_OCTETS_V4: Set[int] = {100, 169, 172, 192, 198, 203}

# Pure public first octets: entirely routable, no reserved sub-ranges
PURE_PUBLIC_FIRST_OCTETS_V4: Set[int] = (
    set(range(256)) - RESERVED_FIRST_OCTETS_V4 - MIXED_FIRST_OCTETS_V4
)

# --- IPv6 first-byte classification for permutation ---

# Pass-through: special-use, not practical public addresses
IPV6_PASS_THROUGH_FIRST_BYTES: Set[int] = {0x00, 0x01}

# Category A: ULA (fc/fd → fc00::/7), link-local (fe → fe80::/10)
IPV6_CAT_A_FIRST_BYTES: Set[int] = {0xFC, 0xFD, 0xFE}

# Category B: multicast
IPV6_CAT_B_FIRST_BYTES: Set[int] = {0xFF}

# Pure public: everything else (250 values)
IPV6_PURE_PUBLIC_FIRST_BYTES: Set[int] = (
    set(range(256))
    - IPV6_PASS_THROUGH_FIRST_BYTES
    - IPV6_CAT_A_FIRST_BYTES
    - IPV6_CAT_B_FIRST_BYTES
)


def compute_ipv4_octet_sets(
    cat_a_entries: List[RangeEntry],
    cat_b_entries: List[IPNetwork],
) -> Tuple[Set[int], Set[int], Set[int]]:
    """Compute (reserved, mixed, pure_public) first-octet sets from Cat A/B lists.

    Returns three disjoint sets that partition {0..255}:
    - reserved: first octets entirely covered by Cat A or Cat B ranges
    - mixed: first octets partially covered (some public, some reserved)
    - pure_public: first octets with no reserved sub-ranges
    """
    reserved: Set[int] = set()
    mixed: Set[int] = set()

    for entry in cat_a_entries:
        net = entry.network
        if not isinstance(net, ipaddress.IPv4Network):
            continue
        first_octet = int(net.network_address) >> 24
        if net.prefixlen <= 8:
            # Covers entire /8 block(s)
            num_octets = 1 << (8 - net.prefixlen)
            for i in range(num_octets):
                reserved.add(first_octet + i)
        else:
            # Partial overlap within a /8 block
            mixed.add(first_octet)

    for net in cat_b_entries:
        if not isinstance(net, ipaddress.IPv4Network):
            continue
        first_octet = int(net.network_address) >> 24
        if net.prefixlen <= 8:
            num_octets = 1 << (8 - net.prefixlen)
            for i in range(num_octets):
                reserved.add(first_octet + i)
        else:
            mixed.add(first_octet)

    # Remove any octet from mixed that is already fully reserved
    mixed -= reserved
    pure_public = set(range(256)) - reserved - mixed
    return reserved, mixed, pure_public


def compute_ipv6_first_byte_sets(
    cat_a_entries: List[RangeEntry],
    cat_b_entries: List[IPNetwork],
) -> Tuple[Set[int], Set[int]]:
    """Compute (reserved, pure_public) first-byte sets from Cat A/B lists.

    Returns two disjoint sets that partition {0..255}:
    - reserved: first bytes covered by any Cat A or Cat B range
    - pure_public: everything else
    """
    reserved: Set[int] = set()

    for entry in cat_a_entries:
        net = entry.network
        if not isinstance(net, ipaddress.IPv6Network):
            continue
        first_byte = int(net.network_address) >> 120
        if net.prefixlen <= 8:
            num_bytes = 1 << (8 - net.prefixlen)
            for i in range(num_bytes):
                reserved.add(first_byte + i)
        else:
            reserved.add(first_byte)

    for net in cat_b_entries:
        if not isinstance(net, ipaddress.IPv6Network):
            continue
        first_byte = int(net.network_address) >> 120
        if net.prefixlen <= 8:
            num_bytes = 1 << (8 - net.prefixlen)
            for i in range(num_bytes):
                reserved.add(first_byte + i)
        else:
            reserved.add(first_byte)

    pure_public = set(range(256)) - reserved
    return reserved, pure_public


def classify_ip(addr: IPAddress) -> Tuple[Category, int]:
    """Classify an IP address and return (category, locked_bits).

    For Category B (pass-through), locked_bits is the full address size (32 or 128).
    For Category C (public), locked_bits is 0.
    For Category A, locked_bits is the range's prefix length.
    """
    if isinstance(addr, ipaddress.IPv4Address):
        # Check Category B first (more specific ranges)
        for net in CATEGORY_B_V4:
            if addr in net:
                return (Category.PASS_THROUGH, 32)

        # Check Category A
        for entry in CATEGORY_A_V4:
            if addr in entry.network:
                return (Category.RANGE_PRESERVED, entry.locked_bits)

        # Category C: public
        return (Category.PUBLIC, 0)
    else:
        # IPv6
        for net in CATEGORY_B_V6:
            if addr in net:
                return (Category.PASS_THROUGH, 128)

        for entry in CATEGORY_A_V6:
            if addr in entry.network:
                return (Category.RANGE_PRESERVED, entry.locked_bits)

        return (Category.PUBLIC, 0)


def is_in_forbidden_range(addr: IPAddress) -> bool:
    """Check if an address falls in any Category A or B range (forbidden for public output)."""
    if isinstance(addr, ipaddress.IPv4Address):
        ranges = FORBIDDEN_OUTPUT_V4
    else:
        ranges = FORBIDDEN_OUTPUT_V6

    for net in ranges:
        if addr in net:
            return True
    return False
