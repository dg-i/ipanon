"""IP address scanner: regex detection, validation, and text replacement."""

from __future__ import annotations

import ipaddress
import re
from typing import List, Match

from ipanon.anonymizer import Anonymizer

# IPv4 pattern: 4 octets of 1-3 digits, optional /prefix
# Uses word boundaries to reject OIDs and version strings
_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
_IPV4_ADDR = rf"{_IPV4_OCTET}(?:\.{_IPV4_OCTET}){{3}}"
_IPV4_CIDR = r"(?:/(?:[0-9]|[12]\d|3[0-2]))?"
_IPV4_PATTERN = rf"(?<!\d\.)(?<!\d)({_IPV4_ADDR})({_IPV4_CIDR})(?!\.\d)(?!\d)"

# IPv6 pattern: match common representations
# Full: 8 groups of hex separated by colons
# Compressed: uses :: for zero runs
# With optional /prefix (0-128)
_HEX4 = r"[0-9a-fA-F]{1,4}"
_IPV6_PATTERN = (
    r"("
    # Full 8-group form
    rf"(?:{_HEX4}:){{7}}{_HEX4}"
    # Compressed forms with groups AFTER :: (most after-groups first to avoid
    # short matches — e.g., 2001:db8::0:0 must not match as just 2001:db8::0)
    rf"|{_HEX4}:(?::{_HEX4}){{1,6}}"
    rf"|(?:{_HEX4}:){{1,2}}(?::{_HEX4}){{1,5}}"
    rf"|(?:{_HEX4}:){{1,3}}(?::{_HEX4}){{1,4}}"
    rf"|(?:{_HEX4}:){{1,4}}(?::{_HEX4}){{1,3}}"
    rf"|(?:{_HEX4}:){{1,5}}(?::{_HEX4}){{1,2}}"
    rf"|(?:{_HEX4}:){{1,6}}:{_HEX4}"
    # :: with groups only after (no prefix groups)
    rf"|:(?::{_HEX4}){{1,7}}"
    # Compressed forms ending with :: (no groups after)
    rf"|(?:{_HEX4}:){{1,7}}:"
    # ::ffff:1.2.3.4 (IPv4-mapped IPv6)
    r"|::(?:[fF]{4}:)?(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}"
    r"|::"  # :: alone
    r")"
    r"(?:/(?:1[0-2]\d|[1-9]\d?|0))?"  # optional /0 to /128
)

_COMBINED_PATTERN = re.compile(
    rf"(?:{_IPV6_PATTERN}|{_IPV4_PATTERN})",
    re.IGNORECASE,
)


def find_ips(text: str) -> List[Match[str]]:
    """Find all valid IP addresses (IPv4 and IPv6) in text.

    Returns a list of regex Match objects. Each match's group(0) is the
    full matched string (IP + optional CIDR).
    """
    results = []
    for m in _COMBINED_PATTERN.finditer(text):
        full = m.group(0)
        # Validate: try to parse as IP address
        if _is_valid_ip_match(full):
            results.append(m)
    return results


def _is_valid_ip_match(s: str) -> bool:
    """Validate that a regex match is actually a valid IP/CIDR."""
    ip_part = s.split("/")[0] if "/" in s else s
    try:
        ipaddress.ip_address(ip_part)
        return True
    except ValueError:
        return False


def scan_and_replace(text: str, anonymizer: Anonymizer) -> str:
    """Scan text for IP addresses and replace them with anonymized versions.

    Processes matches from right to left to preserve string positions.
    """
    matches = find_ips(text)
    if not matches:
        return text

    # Process from right to left to maintain correct offsets
    result = text
    for m in reversed(matches):
        original = m.group(0)
        anonymized = anonymizer.anonymize(original)
        result = result[: m.start()] + anonymized + result[m.end() :]

    return result
