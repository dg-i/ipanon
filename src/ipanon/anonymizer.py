"""Core anonymization engine with Cat A/B/C dispatch, remapping, and caching."""

from __future__ import annotations

import ipaddress
import os
import sys
from typing import TYPE_CHECKING, Dict, List, Optional, Set, Tuple, Union

from ipanon.permutation import make_permutation, prefix_preserving_permute

if TYPE_CHECKING:
    from ipanon.networks import NetworkRegistry
from ipanon.ranges import (
    CATEGORY_A_V4,
    CATEGORY_A_V6,
    CATEGORY_B_V4,
    CATEGORY_B_V6,
    Category,
    RangeEntry,
    compute_ipv4_octet_sets,
    compute_ipv6_first_byte_sets,
)

IPAddress = Union[ipaddress.IPv4Address, ipaddress.IPv6Address]
IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]


class PassThroughCollisionError(Exception):
    """Raised when an anonymized IP collides with a pass-through prefix."""


class Anonymizer:
    """CIDR-aware IP anonymizer with prefix-preserving permutation.

    Args:
        salt: Reproducible anonymization salt. If None, a random salt is generated.
        remaps: Dict mapping mixed first-octets to pure-public target octets.
        pass_through_prefixes: List of CIDR strings that should not be anonymized.
        allow_pt_collisions: If True, downgrade pass-through collision errors to warnings.
        quiet: If True, suppress all warnings to stderr.
        verbose: If True, show verbose-level warnings (e.g., short-prefix pass-through).
        ignore_subnets: If True, treat sub-/8 IPv4 Cat A ranges as public (Cat C).
            Only 10.0.0.0/8 remains Cat A. Cat B and IPv6 are unaffected.
        ignore_reserved: If True, remove ALL Cat A and Cat B handling. Every IP
            (including loopback, multicast, private ranges) gets fully anonymized
            as Cat C. Affects both IPv4 and IPv6.
        network_registry: If provided, enables subnet-aware host-bit locking.
            The registry determines which bits are permuted (network portion)
            and which are preserved (host portion) for each address.
    """

    def __init__(
        self,
        salt: Optional[str] = None,
        remaps: Optional[Dict[int, int]] = None,
        pass_through_prefixes: Optional[List[str]] = None,
        allow_pt_collisions: bool = False,
        quiet: bool = False,
        verbose: bool = False,
        ignore_subnets: bool = False,
        ignore_reserved: bool = False,
        network_registry: Optional[NetworkRegistry] = None,
    ) -> None:
        self._quiet = quiet
        self._verbose = verbose
        self._ignore_subnets = ignore_subnets
        self._ignore_reserved = ignore_reserved
        self._network_registry = network_registry
        if salt is None:
            salt = os.urandom(16).hex()
            if not quiet:
                print(f"Generated salt: {salt}", file=sys.stderr)
        self._salt = salt
        self._allow_pt_collisions = allow_pt_collisions
        self._cache: Dict[str, str] = {}

        # --- Filter Cat A/B lists based on flags ---
        if ignore_reserved:
            self._active_cat_a_v4: List[RangeEntry] = []
            self._active_cat_a_v6: List[RangeEntry] = []
            self._active_cat_b_v4: List[IPNetwork] = []
            self._active_cat_b_v6: List[IPNetwork] = []
        elif ignore_subnets:
            # Keep only /8 Cat A entries (locked_bits == 8) for IPv4
            self._active_cat_a_v4 = [e for e in CATEGORY_A_V4 if e.locked_bits == 8]
            self._active_cat_a_v6 = list(CATEGORY_A_V6)
            self._active_cat_b_v4 = list(CATEGORY_B_V4)
            self._active_cat_b_v6 = list(CATEGORY_B_V6)
        else:
            self._active_cat_a_v4 = list(CATEGORY_A_V4)
            self._active_cat_a_v6 = list(CATEGORY_A_V6)
            self._active_cat_b_v4 = list(CATEGORY_B_V4)
            self._active_cat_b_v6 = list(CATEGORY_B_V6)

        # --- Compute dynamic first-octet/byte sets ---
        _, self._mixed_first_octets, self._pure_public_first_octets = compute_ipv4_octet_sets(
            self._active_cat_a_v4, self._active_cat_b_v4
        )
        _, self._ipv6_pure_public_first_bytes = compute_ipv6_first_byte_sets(
            self._active_cat_a_v6, self._active_cat_b_v6
        )

        # Parse pass-through prefixes FIRST (before building permutation pools)
        self._pass_through: List[IPNetwork] = []
        pt_excluded_octets: Set[int] = set()
        pt_excluded_bytes: Set[int] = set()
        if pass_through_prefixes:
            for prefix_str in pass_through_prefixes:
                net = ipaddress.ip_network(prefix_str, strict=False)
                self._pass_through.append(net)
                if isinstance(net, ipaddress.IPv4Network):
                    if net.prefixlen == 8:
                        octet = int(net.network_address) >> 24
                        if octet in self._pure_public_first_octets:
                            pt_excluded_octets.add(octet)
                else:  # IPv6
                    if net.prefixlen == 8:
                        byte_val = int(net.network_address) >> 120
                        if byte_val in self._ipv6_pure_public_first_bytes:
                            pt_excluded_bytes.add(byte_val)

        # Parse and validate remaps
        self._remap_table: Dict[int, int] = {}
        remap_targets: Set[int] = set()
        if remaps:
            for source, target in remaps.items():
                if source not in self._mixed_first_octets:
                    raise ValueError(
                        f"Remap source {source} is not a mixed first-octet. "
                        f"Valid mixed octets: {sorted(self._mixed_first_octets)}"
                    )
                if target not in self._pure_public_first_octets:
                    raise ValueError(f"Remap target {target} is not a pure-public first-octet.")
                if target in pt_excluded_octets:
                    raise ValueError(
                        f"Remap target {target} conflicts with --pass-through prefix. "
                        f"Cannot remap to a first-octet that is excluded by a pass-through /8."
                    )
                self._remap_table[source] = target
                remap_targets.add(target)

        # Build first-octet permutation (excluding remap targets + pass-through /8 octets)
        pool = sorted(self._pure_public_first_octets - remap_targets - pt_excluded_octets)
        self._v4_first_octet_perm = make_permutation(pool, salt, "v4:first_octet")

        # Build IPv6 first-byte permutation (excluding pass-through /8 bytes)
        v6_pool = sorted(self._ipv6_pure_public_first_bytes - pt_excluded_bytes)
        self._v6_first_byte_perm = make_permutation(v6_pool, salt, "v6:first_byte")

        # Track warned mixed octets to warn only once
        self._warned_mixed: Set[int] = set()

    def _classify_ip(self, addr: IPAddress) -> Tuple[Category, int]:
        """Classify an IP using the active (filtered) Cat A/B lists.

        Returns (Category, locked_bits) just like ranges.classify_ip(),
        but uses instance-level lists that respect ignore_subnets/ignore_reserved.
        """
        if isinstance(addr, ipaddress.IPv4Address):
            for net in self._active_cat_b_v4:
                if addr in net:
                    return (Category.PASS_THROUGH, 32)
            for entry in self._active_cat_a_v4:
                if addr in entry.network:
                    return (Category.RANGE_PRESERVED, entry.locked_bits)
            return (Category.PUBLIC, 0)
        else:
            for net in self._active_cat_b_v6:
                if addr in net:
                    return (Category.PASS_THROUGH, 128)
            for entry in self._active_cat_a_v6:
                if addr in entry.network:
                    return (Category.RANGE_PRESERVED, entry.locked_bits)
            return (Category.PUBLIC, 0)

    def _warn(self, msg: str) -> None:
        """Print a warning to stderr unless quiet mode is enabled."""
        if not self._quiet:
            print(msg, file=sys.stderr)

    def _verbose_warn(self, msg: str) -> None:
        """Print a warning to stderr only in verbose mode."""
        if self._verbose and not self._quiet:
            print(msg, file=sys.stderr)

    def anonymize(self, addr_str: str) -> str:
        """Anonymize an IP address or CIDR prefix string.

        Returns the anonymized string (with /prefix if input had one).
        """
        if addr_str in self._cache:
            return self._cache[addr_str]

        result = self._anonymize_impl(addr_str)
        self._cache[addr_str] = result
        return result

    def _anonymize_impl(self, addr_str: str) -> str:
        # Parse: separate address from optional prefix length
        has_prefix = "/" in addr_str
        if has_prefix:
            ip_part, prefix_str = addr_str.split("/", 1)
            prefix_len = int(prefix_str)
        else:
            ip_part = addr_str
            prefix_len = None

        # Parse the IP address
        try:
            addr = ipaddress.ip_address(ip_part)
        except ValueError:
            # Not a valid IP, return unchanged
            return addr_str

        is_v4 = isinstance(addr, ipaddress.IPv4Address)
        total_bits = 32 if is_v4 else 128

        # --- Resolve host-bit boundary from network registry ---
        host_boundary: Optional[int] = None
        if self._network_registry is not None:
            host_boundary = self._network_registry.lookup(ip_part)

        # --- Short prefix handling ---
        if prefix_len is not None:
            if is_v4:
                if prefix_len <= 1:
                    return addr_str  # Default route or split default, no warning
                if prefix_len < 8:
                    self._verbose_warn(
                        f"WARNING: Cannot anonymize short prefix {addr_str} "
                        f"(prefix length < /8). Passing through unchanged."
                    )
                    return addr_str
            else:  # IPv6
                if prefix_len <= 1:
                    return addr_str
                if prefix_len < 32:
                    self._verbose_warn(
                        f"WARNING: Cannot anonymize short prefix {addr_str} "
                        f"(prefix length < /32). Passing through unchanged."
                    )
                    return addr_str

        # --- User-defined pass-through ---
        for net in self._pass_through:
            if addr in net:
                return addr_str

        # --- Classify ---
        category, locked_bits = self._classify_ip(addr)

        # --- Category B: pass-through ---
        if category == Category.PASS_THROUGH:
            return addr_str

        # --- Category A: range-preserved ---
        if category == Category.RANGE_PRESERVED:
            return self._anonymize_cat_a(
                addr, prefix_len, is_v4, total_bits, locked_bits, host_boundary
            )

        # --- Category C: public ---
        return self._anonymize_cat_c(addr, prefix_len, is_v4, total_bits, host_boundary)

    def _anonymize_cat_a(
        self,
        addr: IPAddress,
        prefix_len: Optional[int],
        is_v4: bool,
        total_bits: int,
        locked_bits: int,
        host_boundary: Optional[int] = None,
    ) -> str:
        int_val = int(addr)
        # Lock the top locked_bits, permute the rest
        remaining_bits = total_bits - locked_bits
        locked_mask = ((1 << locked_bits) - 1) << remaining_bits
        locked_part = int_val & locked_mask

        host_val = int_val & ((1 << remaining_bits) - 1)

        # Find the range for context
        range_name = self._find_cat_a_range_name(addr, is_v4)
        context = f"v4:catA:{range_name}" if is_v4 else f"v6:catA:{range_name}"

        # Host-bit locking: only permute network portion, preserve host portion
        if host_boundary is not None and locked_bits < host_boundary < total_bits:
            net_bits = host_boundary - locked_bits
            host_bits = total_bits - host_boundary
            net_part = host_val >> host_bits
            host_part = host_val & ((1 << host_bits) - 1)
            anon_net_part = prefix_preserving_permute(net_part, net_bits, self._salt, context)
            anon_host = (anon_net_part << host_bits) | host_part
        else:
            anon_host = prefix_preserving_permute(host_val, remaining_bits, self._salt, context)

        anon_int = locked_part | anon_host

        # CIDR masking: only when input is a network address (host bits all zero)
        if prefix_len is not None:
            host_mask = (1 << (total_bits - prefix_len)) - 1
            if (int_val & host_mask) == 0:
                anon_int &= ((1 << total_bits) - 1) ^ host_mask

        result_addr: IPAddress
        if is_v4:
            result_addr = ipaddress.IPv4Address(anon_int)
        else:
            result_addr = ipaddress.IPv6Address(anon_int)

        if prefix_len is not None:
            return f"{result_addr}/{prefix_len}"
        return str(result_addr)

    def _anonymize_cat_c(
        self,
        addr: IPAddress,
        prefix_len: Optional[int],
        is_v4: bool,
        total_bits: int,
        host_boundary: Optional[int] = None,
    ) -> str:
        int_val = int(addr)

        if is_v4:
            assert isinstance(addr, ipaddress.IPv4Address)
            return self._anonymize_cat_c_v4(addr, int_val, prefix_len, total_bits, host_boundary)
        else:
            assert isinstance(addr, ipaddress.IPv6Address)
            return self._anonymize_cat_c_v6(addr, int_val, prefix_len, total_bits, host_boundary)

    def _anonymize_cat_c_v4(
        self,
        addr: ipaddress.IPv4Address,
        int_val: int,
        prefix_len: Optional[int],
        total_bits: int,
        host_boundary: Optional[int] = None,
    ) -> str:
        first_octet = (int_val >> 24) & 0xFF

        # Determine anonymized first octet
        if first_octet in self._v4_first_octet_perm:
            anon_first_octet = self._v4_first_octet_perm[first_octet]
        elif first_octet in self._remap_table:
            anon_first_octet = self._remap_table[first_octet]
        else:
            # Mixed octet without remap — warn and pass through first octet
            if first_octet not in self._warned_mixed:
                self._warned_mixed.add(first_octet)
                self._warn(
                    f"WARNING: Public IP {addr} has mixed first-octet {first_octet}. "
                    f"Use --remap {first_octet}=<target> for collision-free anonymization."
                )
            anon_first_octet = first_octet

        # Prefix-preserving permutation of bits 8-31
        lower_24 = int_val & 0xFFFFFF

        # Host-bit locking: only permute network portion, preserve host portion
        if host_boundary is not None and 8 < host_boundary < 32:
            net_bits = host_boundary - 8
            host_bits_count = 32 - host_boundary
            net_part = lower_24 >> host_bits_count
            host_part = lower_24 & ((1 << host_bits_count) - 1)
            anon_net = prefix_preserving_permute(
                net_part, net_bits, self._salt, f"v4:{first_octet}"
            )
            anon_lower = (anon_net << host_bits_count) | host_part
        else:
            anon_lower = prefix_preserving_permute(lower_24, 24, self._salt, f"v4:{first_octet}")

        anon_int = (anon_first_octet << 24) | anon_lower

        # CIDR masking: only when input is a network address (host bits all zero)
        if prefix_len is not None:
            host_mask = (1 << (32 - prefix_len)) - 1
            if (int_val & host_mask) == 0:
                anon_int &= 0xFFFFFFFF ^ host_mask

        result_addr = ipaddress.IPv4Address(anon_int)

        # Check pass-through collisions
        self._check_pt_collision(addr, result_addr)

        if prefix_len is not None:
            return f"{result_addr}/{prefix_len}"
        return str(result_addr)

    def _anonymize_cat_c_v6(
        self,
        addr: ipaddress.IPv6Address,
        int_val: int,
        prefix_len: Optional[int],
        total_bits: int,
        host_boundary: Optional[int] = None,
    ) -> str:
        first_byte = (int_val >> 120) & 0xFF

        # Determine anonymized first byte
        if first_byte in self._v6_first_byte_perm:
            anon_first_byte = self._v6_first_byte_perm[first_byte]
        else:
            anon_first_byte = first_byte

        # Prefix-preserving permutation of bits 8-127
        lower_120 = int_val & ((1 << 120) - 1)

        # Host-bit locking: only permute network portion, preserve host portion
        if host_boundary is not None and 8 < host_boundary < 128:
            net_bits = host_boundary - 8
            host_bits_count = 128 - host_boundary
            net_part = lower_120 >> host_bits_count
            host_part = lower_120 & ((1 << host_bits_count) - 1)
            anon_net = prefix_preserving_permute(
                net_part, net_bits, self._salt, f"v6:{first_byte}"
            )
            anon_lower = (anon_net << host_bits_count) | host_part
        else:
            anon_lower = prefix_preserving_permute(lower_120, 120, self._salt, f"v6:{first_byte}")

        anon_int = (anon_first_byte << 120) | anon_lower

        # CIDR masking: only when input is a network address (host bits all zero)
        if prefix_len is not None:
            host_mask = (1 << (128 - prefix_len)) - 1
            if (int_val & host_mask) == 0:
                anon_int &= ((1 << 128) - 1) ^ host_mask

        result_addr = ipaddress.IPv6Address(anon_int)

        # Check pass-through collisions
        self._check_pt_collision(addr, result_addr)

        if prefix_len is not None:
            return f"{result_addr}/{prefix_len}"
        return str(result_addr)

    def _check_pt_collision(self, original: IPAddress, anonymized: IPAddress) -> None:
        for net in self._pass_through:
            if anonymized in net:
                msg = (
                    f"Anonymized IP {anonymized} (from {original}) collides with "
                    f"--pass-through prefix {net}. "
                    f"Options: use --allow-pt-collisions, use a different --salt, "
                    f"or adjust --pass-through prefixes."
                )
                if self._allow_pt_collisions:
                    self._warn(f"WARNING: {msg}")
                    return
                raise PassThroughCollisionError(msg)

    def _find_cat_a_range_name(self, addr: IPAddress, is_v4: bool) -> str:
        entries = self._active_cat_a_v4 if is_v4 else self._active_cat_a_v6
        for entry in entries:
            if addr in entry.network:
                return str(entry.network)
        return "unknown"

    def get_mapping(self) -> Dict[str, str]:
        """Return the current IP mapping cache (input -> output)."""
        return dict(self._cache)
