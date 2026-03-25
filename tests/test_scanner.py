"""Tests for IP scanner: regex detection, validation, and text replacement."""

from __future__ import annotations

from ipanon.anonymizer import Anonymizer
from ipanon.scanner import find_ips, scan_and_replace


class TestFindIPv4:
    """IPv4 regex detection and validation."""

    def test_simple_ip(self):
        matches = find_ips("host 8.8.8.8 is down")
        assert len(matches) == 1
        assert matches[0].group(0) == "8.8.8.8"

    def test_ip_with_cidr(self):
        matches = find_ips("route 10.0.0.0/8")
        assert len(matches) == 1
        assert matches[0].group(0) == "10.0.0.0/8"

    def test_multiple_ips(self):
        matches = find_ips("from 10.0.0.1 to 192.168.1.1")
        assert len(matches) == 2

    def test_rejects_version_number(self):
        """Version-like strings should not be matched."""
        matches = find_ips("version 1.2.3")
        assert len(matches) == 0

    def test_rejects_three_octets(self):
        matches = find_ips("value 1.2.3 here")
        assert len(matches) == 0

    def test_rejects_five_octets(self):
        """OID-like: 1.2.3.4.5 should not match as IP."""
        matches = find_ips("oid 1.2.3.4.5")
        assert len(matches) == 0

    def test_rejects_invalid_octets(self):
        """Octets > 255 should not match."""
        matches = find_ips("value 999.999.999.999")
        assert len(matches) == 0

    def test_rejects_octet_256(self):
        matches = find_ips("addr 256.0.0.1")
        assert len(matches) == 0

    def test_ip_at_start_of_line(self):
        matches = find_ips("10.0.0.1 is the gateway")
        assert len(matches) == 1

    def test_ip_at_end_of_line(self):
        matches = find_ips("gateway is 10.0.0.1")
        assert len(matches) == 1

    def test_ip_in_brackets(self):
        matches = find_ips("[10.0.0.1]")
        assert len(matches) == 1
        assert matches[0].group(0) == "10.0.0.1"

    def test_ip_with_port_doesnt_include_port(self):
        matches = find_ips("server 10.0.0.1:8080")
        assert len(matches) == 1
        assert matches[0].group(0) == "10.0.0.1"

    def test_cidr_32(self):
        matches = find_ips("host 10.0.0.1/32")
        assert len(matches) == 1
        assert matches[0].group(0) == "10.0.0.1/32"

    def test_rejects_cidr_33(self):
        """IPv4 CIDR > 32 is invalid."""
        matches = find_ips("10.0.0.0/33")
        # Should match the IP but not include /33
        assert len(matches) == 1
        assert matches[0].group(0) == "10.0.0.0"

    def test_all_zeros(self):
        matches = find_ips("route 0.0.0.0/0")
        assert len(matches) == 1
        assert matches[0].group(0) == "0.0.0.0/0"

    def test_broadcast(self):
        matches = find_ips("255.255.255.255")
        assert len(matches) == 1


class TestFindIPv6:
    """IPv6 regex detection."""

    def test_full_ipv6(self):
        matches = find_ips("addr 2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert len(matches) == 1

    def test_compressed_ipv6(self):
        matches = find_ips("addr 2001:db8::1")
        assert len(matches) == 1

    def test_loopback(self):
        matches = find_ips("addr ::1")
        assert len(matches) == 1

    def test_unspecified(self):
        matches = find_ips("addr ::")
        assert len(matches) == 1

    def test_ipv6_cidr(self):
        matches = find_ips("route 2001:db8::/32")
        assert len(matches) == 1
        assert matches[0].group(0) == "2001:db8::/32"

    def test_ipv6_link_local(self):
        matches = find_ips("addr fe80::1")
        assert len(matches) == 1

    def test_ipv6_with_prefix(self):
        matches = find_ips("net fd00::/64")
        assert len(matches) == 1
        assert matches[0].group(0) == "fd00::/64"

    def test_ipv6_multiple_groups_after_doublecolon(self):
        """Addresses like 2001:db8::0:0 must match all groups after ::."""
        matches = find_ips("route 2001:db8::0:0/104;")
        assert len(matches) == 1
        assert matches[0].group(0) == "2001:db8::0:0/104"

    def test_ipv6_compressed_with_trailing_groups(self):
        """Addresses like 2001:db8::f:0 must capture all trailing groups."""
        matches = find_ips("addr 2001:db8::f:0/112;")
        assert len(matches) == 1
        assert matches[0].group(0) == "2001:db8::f:0/112"

    def test_ipv6_three_groups_after_doublecolon(self):
        matches = find_ips("addr 2001:db8::1:2:3")
        assert len(matches) == 1
        assert matches[0].group(0) == "2001:db8::1:2:3"


class TestScanAndReplace:
    """End-to-end text scanning and replacement."""

    def test_replaces_ipv4(self):
        a = Anonymizer("salt")
        result = scan_and_replace("server 8.8.8.8 is up", a)
        assert "8.8.8.8" not in result
        assert "server" in result
        assert "is up" in result

    def test_replaces_cidr(self):
        a = Anonymizer("salt")
        # Use a /24 so there are bits to anonymize after masking
        result = scan_and_replace("route 10.1.2.0/24 via gw", a)
        assert "10.1.2.0/24" not in result
        assert "/24" in result  # prefix length preserved

    def test_preserves_non_ip_text(self):
        a = Anonymizer("salt")
        text = "no IPs here, just text"
        assert scan_and_replace(text, a) == text

    def test_replaces_multiple_ips(self):
        a = Anonymizer("salt")
        result = scan_and_replace("from 10.0.0.1 to 10.0.0.2", a)
        assert "10.0.0.1" not in result
        assert "10.0.0.2" not in result

    def test_deterministic(self):
        a = Anonymizer("salt")
        text = "host 8.8.8.8"
        assert scan_and_replace(text, a) == scan_and_replace(text, a)

    def test_replaces_ipv6(self):
        a = Anonymizer("salt")
        result = scan_and_replace("server 2001:db8::1 is up", a)
        assert "2001:db8::1" not in result

    def test_multiline(self):
        a = Anonymizer("salt")
        text = "host 10.0.0.1\nhost 10.0.0.2\nhost 10.0.0.3\n"
        result = scan_and_replace(text, a)
        assert "10.0.0.1" not in result
        assert "10.0.0.2" not in result
        assert "10.0.0.3" not in result
        assert result.count("\n") == 3  # structure preserved

    def test_cat_b_unchanged(self):
        a = Anonymizer("salt")
        result = scan_and_replace("loopback 127.0.0.1", a)
        assert "127.0.0.1" in result

    def test_version_string_not_replaced(self):
        a = Anonymizer("salt")
        text = "version 2.1.3 and server 8.8.8.8"
        result = scan_and_replace(text, a)
        assert "2.1.3" in result  # version string preserved
        assert "8.8.8.8" not in result  # IP replaced

    def test_ipv6_compressed_cidr_no_extra_groups(self):
        """Anonymized IPv6 with :: must not produce 9 colon-separated groups."""
        a = Anonymizer("salt")
        result = scan_and_replace("prefix 2001:db8::0:0/104;", a)
        # Extract the IPv6 address part (before /104)
        ip_part = result.split("prefix ")[1].split("/")[0]
        groups = ip_part.split(":")
        # Expanded IPv6 has at most 8 groups; compressed may have fewer with ::
        assert len(groups) <= 8, f"Got {len(groups)} groups: {ip_part}"
