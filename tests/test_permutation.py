"""Tests for permutation algorithms: Fisher-Yates and prefix-preserving HMAC."""

from __future__ import annotations

from ipanon.permutation import make_permutation, prefix_preserving_permute


class TestMakePermutation:
    """Fisher-Yates keyed permutation must be bijective and deterministic."""

    def test_bijection_small(self):
        """Permutation of [0..9] produces exactly the same set of values."""
        values = list(range(10))
        perm = make_permutation(values, "salt", "ctx")
        assert set(perm.values()) == set(values)
        assert len(perm) == 10

    def test_bijection_full_pool(self):
        """Permutation of 215 values is bijective."""
        values = list(range(215))
        perm = make_permutation(values, "salt", "ctx")
        assert set(perm.values()) == set(values)
        assert len(perm) == 215

    def test_deterministic(self):
        """Same inputs produce the same permutation."""
        values = list(range(50))
        perm1 = make_permutation(values, "mysalt", "ctx")
        perm2 = make_permutation(values, "mysalt", "ctx")
        assert perm1 == perm2

    def test_different_salt_different_result(self):
        """Different salts produce different permutations."""
        values = list(range(50))
        perm1 = make_permutation(values, "salt_a", "ctx")
        perm2 = make_permutation(values, "salt_b", "ctx")
        assert perm1 != perm2

    def test_different_context_different_result(self):
        """Different contexts produce different permutations."""
        values = list(range(50))
        perm1 = make_permutation(values, "salt", "ctx_a")
        perm2 = make_permutation(values, "salt", "ctx_b")
        assert perm1 != perm2

    def test_identity_not_default(self):
        """Non-trivial permutation is not the identity (safe with 50 elements)."""
        values = list(range(50))
        perm = make_permutation(values, "test_salt", "ctx")
        identity = {v: v for v in values}
        assert perm != identity

    def test_single_element(self):
        """Single element always maps to itself."""
        perm = make_permutation([42], "salt", "ctx")
        assert perm == {42: 42}


class TestPrefixPreservingPermute:
    """HMAC-based prefix-preserving bit permutation."""

    def test_deterministic(self):
        """Same inputs produce the same output."""
        r1 = prefix_preserving_permute(0b10101010_11001100_00110011, 24, "salt", "ctx")
        r2 = prefix_preserving_permute(0b10101010_11001100_00110011, 24, "salt", "ctx")
        assert r1 == r2

    def test_different_salt(self):
        """Different salts produce different outputs."""
        r1 = prefix_preserving_permute(0xAABBCC, 24, "salt_a", "ctx")
        r2 = prefix_preserving_permute(0xAABBCC, 24, "salt_b", "ctx")
        assert r1 != r2

    def test_output_within_range(self):
        """Output is within the valid bit range."""
        for val in [0, 1, 0xFFFF, 0xFFFFFF]:
            result = prefix_preserving_permute(val, 24, "salt", "ctx")
            assert 0 <= result < (1 << 24)

    def test_bijection_small_space(self):
        """All 2^8 values map to distinct outputs (bijection for 8-bit space)."""
        outputs = set()
        for v in range(256):
            result = prefix_preserving_permute(v, 8, "test_salt", "ctx")
            outputs.add(result)
        assert len(outputs) == 256

    def test_prefix_preservation_shared_prefix(self):
        """IPs sharing a prefix should produce outputs sharing that prefix.

        For two values that share the top K bits, their permuted outputs
        should also share the same top K bits.
        """
        # 0xAA00 and 0xAA01 share the top 15 bits (differ only in last bit)
        r1 = prefix_preserving_permute(0xAA00, 16, "salt", "ctx")
        r2 = prefix_preserving_permute(0xAA01, 16, "salt", "ctx")
        # Top 15 bits should match
        assert (r1 >> 1) == (r2 >> 1)

    def test_prefix_preservation_different_prefix(self):
        """Values with different prefixes should generally get different output prefixes.

        This is probabilistic, but with different top bits it should work.
        """
        r1 = prefix_preserving_permute(0x0000, 16, "salt", "ctx")
        r2 = prefix_preserving_permute(0x8000, 16, "salt", "ctx")
        # Top bit should differ (they had different top bits, and we flip based on prefix)
        assert (r1 >> 15) != (r2 >> 15)

    def test_zero_bits(self):
        """With 0 bits to permute, output should equal input."""
        assert prefix_preserving_permute(0, 0, "salt", "ctx") == 0

    def test_single_bit(self):
        """Single bit permutation: output is 0 or 1."""
        r = prefix_preserving_permute(0, 1, "salt", "ctx")
        assert r in (0, 1)

    def test_bijection_16bit(self):
        """Spot-check: 1000 random 16-bit values all produce distinct outputs."""
        import random

        rng = random.Random(42)
        inputs = rng.sample(range(65536), 1000)
        outputs = set()
        for v in inputs:
            result = prefix_preserving_permute(v, 16, "bijection_salt", "ctx")
            outputs.add(result)
        assert len(outputs) == 1000
