"""Tests for IP range classification."""

from __future__ import annotations

import ipaddress

from ipanon.ranges import (
    CATEGORY_A_V4,
    CATEGORY_A_V6,
    CATEGORY_B_V4,
    CATEGORY_B_V6,
    MIXED_FIRST_OCTETS_V4,
    PURE_PUBLIC_FIRST_OCTETS_V4,
    RESERVED_FIRST_OCTETS_V4,
    Category,
    classify_ip,
    compute_ipv4_octet_sets,
    compute_ipv6_first_byte_sets,
)


class TestFirstOctetSets:
    """The three first-octet sets must partition 0-255 correctly."""

    def test_sets_are_disjoint(self):
        assert PURE_PUBLIC_FIRST_OCTETS_V4 & MIXED_FIRST_OCTETS_V4 == set()
        assert PURE_PUBLIC_FIRST_OCTETS_V4 & RESERVED_FIRST_OCTETS_V4 == set()
        assert MIXED_FIRST_OCTETS_V4 & RESERVED_FIRST_OCTETS_V4 == set()

    def test_sets_cover_all_256(self):
        all_octets = PURE_PUBLIC_FIRST_OCTETS_V4 | MIXED_FIRST_OCTETS_V4 | RESERVED_FIRST_OCTETS_V4
        assert all_octets == set(range(256))

    def test_pure_public_count(self):
        assert len(PURE_PUBLIC_FIRST_OCTETS_V4) == 215

    def test_mixed_count(self):
        assert len(MIXED_FIRST_OCTETS_V4) == 6

    def test_reserved_count(self):
        assert len(RESERVED_FIRST_OCTETS_V4) == 35

    def test_mixed_values(self):
        assert MIXED_FIRST_OCTETS_V4 == {100, 169, 172, 192, 198, 203}

    def test_reserved_includes_expected(self):
        assert 0 in RESERVED_FIRST_OCTETS_V4
        assert 10 in RESERVED_FIRST_OCTETS_V4
        assert 127 in RESERVED_FIRST_OCTETS_V4
        for i in range(224, 256):
            assert i in RESERVED_FIRST_OCTETS_V4


class TestClassifyIPv4:
    """classify_ip should correctly categorize IPv4 addresses."""

    def test_cat_b_loopback(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("127.0.0.1"))
        assert cat == Category.PASS_THROUGH
        assert locked == 32

    def test_cat_b_this_network(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("0.0.0.0"))
        assert cat == Category.PASS_THROUGH

    def test_cat_b_multicast(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("224.0.0.1"))
        assert cat == Category.PASS_THROUGH

    def test_cat_b_broadcast(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("255.255.255.255"))
        assert cat == Category.PASS_THROUGH

    def test_cat_b_test_net_1(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("192.0.2.1"))
        assert cat == Category.PASS_THROUGH

    def test_cat_b_test_net_2(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("198.51.100.1"))
        assert cat == Category.PASS_THROUGH

    def test_cat_b_test_net_3(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("203.0.113.1"))
        assert cat == Category.PASS_THROUGH

    def test_cat_b_benchmarking(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("198.18.0.1"))
        assert cat == Category.PASS_THROUGH

    def test_cat_a_rfc1918_10(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("10.1.2.3"))
        assert cat == Category.RANGE_PRESERVED
        assert locked == 8

    def test_cat_a_rfc1918_172(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("172.16.0.1"))
        assert cat == Category.RANGE_PRESERVED
        assert locked == 12

    def test_cat_a_rfc1918_192(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("192.168.1.1"))
        assert cat == Category.RANGE_PRESERVED
        assert locked == 16

    def test_cat_a_cgnat(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("100.64.0.1"))
        assert cat == Category.RANGE_PRESERVED
        assert locked == 10

    def test_cat_a_link_local(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("169.254.1.1"))
        assert cat == Category.RANGE_PRESERVED
        assert locked == 16

    def test_cat_c_public(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("8.8.8.8"))
        assert cat == Category.PUBLIC
        assert locked == 0

    def test_cat_c_another_public(self):
        cat, locked = classify_ip(ipaddress.IPv4Address("1.1.1.1"))
        assert cat == Category.PUBLIC

    def test_mixed_octet_public_portion_172(self):
        """172.15.0.1 is public (below 172.16.0.0/12 range)."""
        cat, _ = classify_ip(ipaddress.IPv4Address("172.15.0.1"))
        assert cat == Category.PUBLIC

    def test_mixed_octet_public_portion_100(self):
        """100.0.0.1 is public (below 100.64.0.0/10 CGNAT range)."""
        cat, _ = classify_ip(ipaddress.IPv4Address("100.0.0.1"))
        assert cat == Category.PUBLIC

    def test_mixed_octet_public_portion_169(self):
        """169.0.0.1 is public (not in 169.254.0.0/16)."""
        cat, _ = classify_ip(ipaddress.IPv4Address("169.0.0.1"))
        assert cat == Category.PUBLIC

    def test_mixed_octet_public_portion_192(self):
        """192.1.0.1 is public (not in any 192.x reserved range)."""
        cat, _ = classify_ip(ipaddress.IPv4Address("192.1.0.1"))
        assert cat == Category.PUBLIC

    def test_mixed_octet_public_portion_198(self):
        """198.0.0.1 is public (below 198.18.0.0/15)."""
        cat, _ = classify_ip(ipaddress.IPv4Address("198.0.0.1"))
        assert cat == Category.PUBLIC

    def test_mixed_octet_public_portion_203(self):
        """203.1.0.1 is public (not in 203.0.113.0/24)."""
        cat, _ = classify_ip(ipaddress.IPv4Address("203.1.0.1"))
        assert cat == Category.PUBLIC


class TestClassifyIPv6:
    """classify_ip should correctly categorize IPv6 addresses."""

    def test_cat_b_unspecified(self):
        cat, _ = classify_ip(ipaddress.IPv6Address("::"))
        assert cat == Category.PASS_THROUGH

    def test_cat_b_loopback(self):
        cat, _ = classify_ip(ipaddress.IPv6Address("::1"))
        assert cat == Category.PASS_THROUGH

    def test_cat_b_multicast(self):
        cat, _ = classify_ip(ipaddress.IPv6Address("ff02::1"))
        assert cat == Category.PASS_THROUGH

    def test_cat_b_v4mapped(self):
        cat, _ = classify_ip(ipaddress.IPv6Address("::ffff:192.168.1.1"))
        assert cat == Category.PASS_THROUGH

    def test_cat_b_special_use_0000(self):
        """0000::/8 is special-use, should pass through."""
        cat, _ = classify_ip(ipaddress.IPv6Address("0000:ffff:0:0:0::1"))
        assert cat == Category.PASS_THROUGH

    def test_cat_b_special_use_0100(self):
        """0100::/8 is special-use, should pass through."""
        cat, _ = classify_ip(ipaddress.IPv6Address("0100::1234"))
        assert cat == Category.PASS_THROUGH

    def test_cat_b_special_use_ffff_shifted(self):
        """::ffff:0:0:0 (different from ::ffff:0:0) should also pass through."""
        # ::ffff:0:0:0 = 0000:0000:0000:0000:ffff:0000:0000:0000
        # First byte 0x00 → in 0000::/8 → Cat B
        cat, _ = classify_ip(ipaddress.IPv6Address("::ffff:0:0:0"))
        assert cat == Category.PASS_THROUGH

    def test_cat_a_ula(self):
        cat, locked = classify_ip(ipaddress.IPv6Address("fd00::1"))
        assert cat == Category.RANGE_PRESERVED
        assert locked == 7

    def test_cat_a_link_local(self):
        cat, locked = classify_ip(ipaddress.IPv6Address("fe80::1"))
        assert cat == Category.RANGE_PRESERVED
        assert locked == 10

    def test_cat_c_public(self):
        cat, _ = classify_ip(ipaddress.IPv6Address("2001:db8::1"))
        assert cat == Category.PUBLIC

    def test_cat_c_google_dns(self):
        cat, _ = classify_ip(ipaddress.IPv6Address("2001:4860:4860::8888"))
        assert cat == Category.PUBLIC


class TestIPv6FirstByteClassification:
    """IPv6 first-byte sets for permutation."""

    def test_pass_through_bytes(self):
        from ipanon.ranges import IPV6_PASS_THROUGH_FIRST_BYTES

        assert 0x00 in IPV6_PASS_THROUGH_FIRST_BYTES
        assert 0x01 in IPV6_PASS_THROUGH_FIRST_BYTES

    def test_cat_a_bytes(self):
        from ipanon.ranges import IPV6_CAT_A_FIRST_BYTES

        assert 0xFC in IPV6_CAT_A_FIRST_BYTES
        assert 0xFD in IPV6_CAT_A_FIRST_BYTES
        assert 0xFE in IPV6_CAT_A_FIRST_BYTES

    def test_cat_b_bytes(self):
        from ipanon.ranges import IPV6_CAT_B_FIRST_BYTES

        assert 0xFF in IPV6_CAT_B_FIRST_BYTES

    def test_pure_public_bytes(self):
        from ipanon.ranges import IPV6_PURE_PUBLIC_FIRST_BYTES

        assert len(IPV6_PURE_PUBLIC_FIRST_BYTES) == 250
        assert 0x20 in IPV6_PURE_PUBLIC_FIRST_BYTES  # 2xxx: addresses

    def test_ipv6_byte_sets_cover_all_256(self):
        from ipanon.ranges import (
            IPV6_CAT_A_FIRST_BYTES,
            IPV6_CAT_B_FIRST_BYTES,
            IPV6_PASS_THROUGH_FIRST_BYTES,
            IPV6_PURE_PUBLIC_FIRST_BYTES,
        )

        all_bytes = (
            IPV6_PASS_THROUGH_FIRST_BYTES
            | IPV6_CAT_A_FIRST_BYTES
            | IPV6_CAT_B_FIRST_BYTES
            | IPV6_PURE_PUBLIC_FIRST_BYTES
        )
        assert all_bytes == set(range(256))


class TestComputeIPv4OctetSets:
    """Dynamic computation of IPv4 first-octet sets."""

    def test_default_lists_match_static_constants(self):
        reserved, mixed, pure_public = compute_ipv4_octet_sets(CATEGORY_A_V4, CATEGORY_B_V4)
        assert reserved == RESERVED_FIRST_OCTETS_V4
        assert mixed == MIXED_FIRST_OCTETS_V4
        assert pure_public == PURE_PUBLIC_FIRST_OCTETS_V4

    def test_only_slash8_cat_a(self):
        """With only /8 Cat A entries, sub-/8 entries become mixed → public."""

        cat_a_v4_slash8 = [e for e in CATEGORY_A_V4 if e.locked_bits == 8]
        reserved, mixed, pure_public = compute_ipv4_octet_sets(cat_a_v4_slash8, CATEGORY_B_V4)
        # 172, 100, 169 are no longer reserved or mixed via Cat A
        # But 192 and 198, 203 remain mixed due to Cat B sub-ranges
        assert 172 not in reserved and 172 not in mixed
        assert 172 in pure_public
        assert 100 not in reserved
        assert 169 not in reserved
        # 192 has Cat B sub-ranges (192.0.0.0/24, 192.0.2.0/24) → still mixed
        assert 192 in mixed
        # 198 has Cat B sub-ranges (198.18.0.0/15, 198.51.100.0/24) → still mixed
        assert 198 in mixed
        # 203 has Cat B sub-range (203.0.113.0/24) → still mixed
        assert 203 in mixed

    def test_empty_lists_all_pure_public(self):
        reserved, mixed, pure_public = compute_ipv4_octet_sets([], [])
        assert reserved == set()
        assert mixed == set()
        assert pure_public == set(range(256))

    def test_sets_always_partition(self):
        """Any combination of inputs must produce a partition of {0..255}."""

        cat_a_v4_slash8 = [e for e in CATEGORY_A_V4 if e.locked_bits == 8]
        reserved, mixed, pure_public = compute_ipv4_octet_sets(cat_a_v4_slash8, CATEGORY_B_V4)
        assert reserved & mixed == set()
        assert reserved & pure_public == set()
        assert mixed & pure_public == set()
        assert reserved | mixed | pure_public == set(range(256))


class TestComputeIPv6FirstByteSets:
    """Dynamic computation of IPv6 first-byte sets."""

    def test_default_lists_match_static_constants(self):
        from ipanon.ranges import IPV6_PURE_PUBLIC_FIRST_BYTES

        reserved, pure_public = compute_ipv6_first_byte_sets(CATEGORY_A_V6, CATEGORY_B_V6)
        assert pure_public == IPV6_PURE_PUBLIC_FIRST_BYTES
        assert len(pure_public) == 250

    def test_empty_lists_all_pure_public(self):
        reserved, pure_public = compute_ipv6_first_byte_sets([], [])
        assert reserved == set()
        assert pure_public == set(range(256))

    def test_sets_always_partition(self):
        reserved, pure_public = compute_ipv6_first_byte_sets(CATEGORY_A_V6, CATEGORY_B_V6)
        assert reserved & pure_public == set()
        assert reserved | pure_public == set(range(256))
