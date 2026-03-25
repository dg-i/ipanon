"""Permutation algorithms for IP anonymization.

Provides:
- Fisher-Yates keyed shuffle for first-octet/first-byte permutation
- HMAC-based prefix-preserving bit permutation for remaining bits
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Dict, List


def _keyed_random_int(salt: str, context: str, index: int, modulus: int) -> int:
    """Derive a deterministic random integer in [0, modulus) from salt+context+index."""
    key = salt.encode("utf-8")
    msg = f"{context}:{index}".encode("utf-8")
    digest = hmac.new(key, msg, hashlib.sha256).digest()
    # Use first 8 bytes as a 64-bit unsigned integer
    value = int.from_bytes(digest[:8], "big")
    return value % modulus


def make_permutation(values: List[int], salt: str, context: str) -> Dict[int, int]:
    """Create a bijective permutation of values using Fisher-Yates with keyed randomness.

    Returns a dict mapping each input value to its permuted output value.
    Deterministic given the same salt and context.
    """
    arr = list(values)
    n = len(arr)
    for i in range(n - 1, 0, -1):
        j = _keyed_random_int(salt, context, i, i + 1)
        arr[i], arr[j] = arr[j], arr[i]
    return dict(zip(values, arr))


def prefix_preserving_permute(value: int, num_bits: int, salt: str, context: str) -> int:
    """Apply prefix-preserving HMAC-based bit permutation.

    For each bit position i (0 = most significant of the num_bits range),
    compute a flip bit from HMAC keyed by salt, using the prefix of bits
    already determined as context. XOR the original bit with the flip bit.

    This ensures that two values sharing a K-bit prefix will produce outputs
    that also share a K-bit prefix (prefix-preserving property).
    """
    if num_bits == 0:
        return 0

    key = salt.encode("utf-8")
    result = 0
    for i in range(num_bits):
        # Build prefix from original bits [0..i)
        prefix_bits = (value >> (num_bits - i)) & ((1 << i) - 1) if i > 0 else 0
        prefix_str = format(prefix_bits, f"0{i}b") if i > 0 else ""

        msg = f"{context}:{i}:{prefix_str}".encode("utf-8")
        digest = hmac.new(key, msg, hashlib.sha256).digest()
        flip = digest[0] & 1

        # Get the original bit at position i (MSB-first)
        orig_bit = (value >> (num_bits - 1 - i)) & 1
        new_bit = orig_bit ^ flip
        result = (result << 1) | new_bit

    return result
