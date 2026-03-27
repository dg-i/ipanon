"""Tests for NetworkRegistry: subnet collection and lowest-host-boundary lookup."""

from __future__ import annotations

import pytest

from ipanon.networks import NetworkRegistry


class TestNetworkEntry:
    """Test NetworkEntry dataclass."""

    def test_plain_cidr_entry(self) -> None:
        """Plain CIDR creates entry where network prefix == host_boundary."""
        registry = NetworkRegistry()
        registry.add("10.1.2.0/24")
        entries = registry.entries()
        assert len(entries) == 1
        assert str(entries[0].network) == "10.1.2.0/24"
        assert entries[0].host_boundary == 24

    def test_range_cidr_entry(self) -> None:
        """Range CIDR creates entry with different match scope and host boundary."""
        registry = NetworkRegistry()
        registry.add("10.0.0.0/8-24")
        entries = registry.entries()
        assert len(entries) == 1
        assert str(entries[0].network) == "10.0.0.0/8"
        assert entries[0].host_boundary == 24

    def test_interface_notation(self) -> None:
        """Interface notation (host bits set) extracts correct network."""
        registry = NetworkRegistry()
        registry.add("11.2.3.65/29")
        entries = registry.entries()
        assert str(entries[0].network) == "11.2.3.64/29"
        assert entries[0].host_boundary == 29

    def test_interface_notation_range(self) -> None:
        """Range notation with host bits in address."""
        registry = NetworkRegistry()
        registry.add("10.1.2.5/16-24")
        entries = registry.entries()
        assert str(entries[0].network) == "10.1.0.0/16"
        assert entries[0].host_boundary == 24


class TestNetworkRegistryAdd:
    """Test adding networks to registry."""

    def test_range_boundary_less_than_prefix_raises(self) -> None:
        """Host boundary must be >= match prefix."""
        registry = NetworkRegistry()
        with pytest.raises(ValueError, match="host boundary.*must be >="):
            registry.add("10.0.0.0/24-16")

    def test_range_boundary_equals_prefix(self) -> None:
        """Range with boundary == prefix is same as plain CIDR."""
        registry = NetworkRegistry()
        registry.add("10.1.2.0/24-24")
        entries = registry.entries()
        assert entries[0].host_boundary == 24

    def test_deduplication(self) -> None:
        """Same network from different host addresses counted once."""
        registry = NetworkRegistry()
        registry.add("10.1.2.1/24")
        registry.add("10.1.2.200/24")
        entries = registry.entries()
        assert len(entries) == 1

    def test_ipv6_plain(self) -> None:
        """IPv6 plain CIDR."""
        registry = NetworkRegistry()
        registry.add("2001:db8::/48")
        entries = registry.entries()
        assert str(entries[0].network) == "2001:db8::/48"
        assert entries[0].host_boundary == 48

    def test_ipv6_range(self) -> None:
        """IPv6 range notation."""
        registry = NetworkRegistry()
        registry.add("2001:db8::/32-64")
        entries = registry.entries()
        assert str(entries[0].network) == "2001:db8::/32"
        assert entries[0].host_boundary == 64

    def test_ipv4_boundary_exceeds_32_raises(self) -> None:
        """IPv4 host boundary cannot exceed 32."""
        registry = NetworkRegistry()
        with pytest.raises(ValueError):
            registry.add("10.0.0.0/8-33")

    def test_ipv6_boundary_exceeds_128_raises(self) -> None:
        """IPv6 host boundary cannot exceed 128."""
        registry = NetworkRegistry()
        with pytest.raises(ValueError):
            registry.add("2001:db8::/32-129")


class TestNetworkRegistryLookup:
    """Test address lookup in registry."""

    def test_basic_match(self) -> None:
        """IP in a registered network returns host_boundary."""
        registry = NetworkRegistry()
        registry.add("10.1.2.0/24")
        assert registry.lookup("10.1.2.5") == 24

    def test_no_match(self) -> None:
        """IP not in any registered network returns None."""
        registry = NetworkRegistry()
        registry.add("10.1.2.0/24")
        assert registry.lookup("192.168.1.1") is None

    def test_empty_registry(self) -> None:
        """Empty registry returns None."""
        registry = NetworkRegistry()
        assert registry.lookup("10.1.2.5") is None

    def test_lowest_host_boundary_wins(self) -> None:
        """Lowest host_boundary wins among all matching entries."""
        registry = NetworkRegistry()
        registry.add("10.0.0.0/8-28")  # prefix=8, host_boundary=28
        registry.add("10.0.0.0/16-24")  # prefix=16, host_boundary=24
        # 10.0.1.5 is in both /8 and /16; /8 has boundary 28, /16 has 24 → 24 wins
        assert registry.lookup("10.0.1.5") == 24

    def test_lowest_host_boundary_wins_reversed_add_order(self) -> None:
        """Lowest host_boundary wins regardless of add order."""
        registry = NetworkRegistry()
        registry.add("10.0.0.0/16-24")  # prefix=16, host_boundary=24
        registry.add("10.0.0.0/8-28")  # prefix=8, host_boundary=28
        assert registry.lookup("10.0.1.5") == 24

    def test_non_overlapping_networks(self) -> None:
        """Non-overlapping networks match independently."""
        registry = NetworkRegistry()
        registry.add("10.1.2.0/24")
        registry.add("192.168.1.0/29")
        assert registry.lookup("10.1.2.5") == 24
        assert registry.lookup("192.168.1.3") == 29

    def test_ipv6_lookup(self) -> None:
        """IPv6 address lookup."""
        registry = NetworkRegistry()
        registry.add("2001:db8::/32-64")
        assert registry.lookup("2001:db8:1::1") == 64
        assert registry.lookup("2001:db9::1") is None

    def test_range_cidr_lookup(self) -> None:
        """Range CIDR returns host_boundary, not match prefix."""
        registry = NetworkRegistry()
        registry.add("172.16.0.0/12-24")
        assert registry.lookup("172.20.1.5") == 24

    def test_mixed_v4_and_v6(self) -> None:
        """Registry with both IPv4 and IPv6 entries lookups independently."""
        registry = NetworkRegistry()
        registry.add("10.0.0.0/8-24")
        registry.add("2001:db8::/32-64")
        # IPv4 matches IPv4 entry
        assert registry.lookup("10.1.2.5") == 24
        # IPv6 matches IPv6 entry
        assert registry.lookup("2001:db8:1::1") == 64
        # IPv4 doesn't match IPv6 and vice versa
        assert registry.lookup("192.168.1.1") is None
        assert registry.lookup("2001:db9::1") is None


class TestNetworkRegistryLoadFile:
    """Test loading from file."""

    def test_load_file(self, tmp_path) -> None:
        """Load networks from file."""
        f = tmp_path / "nets.txt"
        f.write_text("# A comment\n10.0.0.0/8-24\n\n192.168.1.0/29\n")
        registry = NetworkRegistry()
        registry.load_file(str(f))
        assert registry.lookup("10.1.2.5") == 24
        assert registry.lookup("192.168.1.3") == 29

    def test_load_file_ignores_comments_and_blanks(self, tmp_path) -> None:
        """Comments and blank lines are ignored."""
        f = tmp_path / "nets.txt"
        f.write_text("# comment\n\n  # indented comment\n10.1.0.0/16\n  \n")
        registry = NetworkRegistry()
        registry.load_file(str(f))
        entries = registry.entries()
        assert len(entries) == 1


class TestNetworkRegistryLoadFromText:
    """Test auto-collection from text."""

    def test_auto_collect(self) -> None:
        """Collect CIDRs from config text."""
        text = """
interface GigabitEthernet0/0
 ip address 10.1.2.65 255.255.255.248
 ip address 10.1.2.65/29
!
router ospf 1
 network 192.168.1.0/24 area 0
"""
        registry = NetworkRegistry()
        registry.load_from_text(text)
        # 10.1.2.65/29 → network 10.1.2.64/29 (addresses .64-.71)
        assert registry.lookup("10.1.2.65") == 29
        assert registry.lookup("10.1.2.70") == 29
        assert registry.lookup("10.1.2.1") is None  # not in .64/29
        assert registry.lookup("192.168.1.5") == 24


class TestNetworkRegistryWarnOverlaps:
    """Test overlap warning."""

    def test_warns_on_overlap(self, capsys) -> None:
        """Overlapping networks produce a warning."""
        registry = NetworkRegistry()
        registry.add("10.0.0.0/8")
        registry.add("10.1.2.0/29")
        registry.warn_overlaps()
        captured = capsys.readouterr()
        assert "10.1.2.0/29" in captured.err
        assert "redundant" in captured.err.lower() or "contained" in captured.err.lower()

    def test_no_warning_without_overlap(self, capsys) -> None:
        """Non-overlapping networks produce no warning."""
        registry = NetworkRegistry()
        registry.add("10.0.0.0/8")
        registry.add("192.168.0.0/16")
        registry.warn_overlaps()
        captured = capsys.readouterr()
        assert captured.err == ""


class TestNetworkRegistryEntries:
    """Test entries export for mapping file."""

    def test_entries_as_specs(self) -> None:
        """Export entries as spec strings for mapping file."""
        registry = NetworkRegistry()
        registry.add("10.0.0.0/8-24")
        registry.add("192.168.1.0/29")
        specs = registry.to_spec_list()
        assert "10.0.0.0/8-24" in specs
        assert "192.168.1.0/29" in specs

    def test_plain_cidr_spec(self) -> None:
        """Plain CIDR exported without range notation."""
        registry = NetworkRegistry()
        registry.add("192.168.1.0/24")
        specs = registry.to_spec_list()
        assert specs == ["192.168.1.0/24"]
