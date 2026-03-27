"""Network registry for subnet-aware host-bit locking.

Provides a registry of subnets that determines which bits are permuted
(network portion) and which are preserved (host portion) during anonymization.
"""

from __future__ import annotations

import ipaddress
import sys
from dataclasses import dataclass
from typing import List, Optional, Union

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


@dataclass
class NetworkEntry:
    """A network with its match scope and host-bit boundary.

    For plain CIDR '10.1.2.0/24': network=10.1.2.0/24, host_boundary=24
    For range CIDR '10.0.0.0/8-24': network=10.0.0.0/8, host_boundary=24
    """

    network: IPNetwork
    host_boundary: int


class NetworkRegistry:
    """Collects subnets and provides lowest-host-boundary lookup for host-bit locking.

    When an address matches multiple entries, the entry with the lowest
    host_boundary wins (fewest bits anonymized, most host bits preserved).

    Supports two network specification formats:
    - Plain CIDR: '10.1.2.0/24' — match scope and host boundary are both /24
    - Range CIDR: '10.0.0.0/8-24' — match scope is /8, host boundary is /24

    Interface notation is accepted (host bits in address are masked off).
    """

    def __init__(self) -> None:
        self._v4_entries: List[NetworkEntry] = []
        self._v6_entries: List[NetworkEntry] = []

    def add(self, spec: str) -> None:
        """Add a network spec to the registry.

        Args:
            spec: Network specification. Either plain CIDR ('10.1.2.0/24')
                or range ('10.0.0.0/8-24'). Interface notation accepted.

        Raises:
            ValueError: If host boundary < match prefix or exceeds address size.
        """
        spec = spec.strip()
        if "/" not in spec:
            raise ValueError(f"Network spec must include prefix length: {spec}")

        prefix_part = spec.split("/", 1)[1]
        if "-" in prefix_part:
            # Range notation: A/X-Y
            addr_part = spec.split("/", 1)[0]
            match_str, boundary_str = prefix_part.split("-", 1)
            match_prefix = int(match_str)
            host_boundary = int(boundary_str)
            net = ipaddress.ip_network(f"{addr_part}/{match_prefix}", strict=False)

            max_bits = 32 if isinstance(net, ipaddress.IPv4Network) else 128
            if host_boundary < match_prefix:
                raise ValueError(
                    f"host boundary {host_boundary} must be >= "
                    f"match prefix {match_prefix} in '{spec}'"
                )
            if host_boundary > max_bits:
                raise ValueError(
                    f"host boundary {host_boundary} exceeds "
                    f"{'32' if max_bits == 32 else '128'} for '{spec}'"
                )
        else:
            net = ipaddress.ip_network(spec, strict=False)
            host_boundary = net.prefixlen

        entry = NetworkEntry(network=net, host_boundary=host_boundary)

        # Add to appropriate list, avoiding duplicates
        entries = self._v4_entries if isinstance(net, ipaddress.IPv4Network) else self._v6_entries
        for existing in entries:
            if existing.network == net and existing.host_boundary == host_boundary:
                return  # Deduplicate
        entries.append(entry)
        # Keep sorted by prefix length ascending (least specific first)
        entries.sort(key=lambda e: e.network.prefixlen)

    def lookup(self, addr_str: str) -> Optional[int]:
        """Find the host-bit boundary for an address.

        Returns the lowest host_boundary among all matching entries
        (fewest bits anonymized, most host bits preserved).
        Returns None if no match.
        """
        try:
            addr = ipaddress.ip_address(addr_str)
        except ValueError:
            return None

        entries = self._v4_entries if isinstance(addr, ipaddress.IPv4Address) else self._v6_entries

        best: Optional[int] = None
        for entry in entries:
            if addr in entry.network:
                if best is None or entry.host_boundary < best:
                    best = entry.host_boundary
        return best

    def entries(self) -> List[NetworkEntry]:
        """Return all entries (v4 + v6)."""
        return list(self._v4_entries) + list(self._v6_entries)

    def to_spec_list(self) -> List[str]:
        """Export entries as spec strings for the mapping file."""
        result: List[str] = []
        for entry in self._v4_entries + self._v6_entries:
            net_str = str(entry.network)
            if entry.host_boundary != entry.network.prefixlen:
                result.append(f"{net_str}-{entry.host_boundary}")
            else:
                result.append(net_str)
        return result

    def warn_overlaps(self) -> None:
        """Print warnings to stderr for redundant overlapping networks."""
        for entries in (self._v4_entries, self._v6_entries):
            for i, inner in enumerate(entries):
                for outer in entries[:i]:
                    if (
                        outer.network.prefixlen < inner.network.prefixlen
                        and inner.network.subnet_of(
                            outer.network  # type: ignore[arg-type]
                        )
                    ):
                        print(
                            f"WARNING: Network {inner.network} is contained in "
                            f"{outer.network} (redundant — {outer.network} "
                            f"already covers it)",
                            file=sys.stderr,
                        )
                        break  # Only warn once per inner entry

    def load_file(self, path: str) -> None:
        """Load network specs from a file, one per line.

        Blank lines and lines starting with # are ignored.
        """
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                self.add(line)

    def load_from_text(self, text: str) -> None:
        """Auto-collect CIDR patterns from text (e.g., router config).

        Only collects entries with explicit prefix lengths. Plain CIDR only
        (no range notation in auto-collected text).
        """
        # Import here to avoid circular dependency
        from ipanon.scanner import extract_cidrs

        for cidr in extract_cidrs(text):
            self.add(cidr)
