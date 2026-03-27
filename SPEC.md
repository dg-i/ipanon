# ipanon — CIDR-Aware IP Anonymizer: Complete Specification

This specification contains everything needed to implement ipanon from scratch.
It covers the algorithm design, all data tables, exact HMAC constructions,
regex patterns, CLI interface, project structure, and expected test behavior.

---

## 1. Project Setup

### 1.1 Project Structure

```
pyproject.toml
.gitignore
LICENSE
README.md
API.md
SPEC.md
.github/
  workflows/
    publish.yml
src/
  ipanon/
    __init__.py
    ranges.py
    permutation.py
    anonymizer.py
    networks.py
    scanner.py
    cli.py
tests/
  __init__.py          # empty
  test_ranges.py
  test_permutation.py
  test_anonymizer.py
  test_networks.py
  test_scanner.py
  test_cli.py
```

### 1.2 pyproject.toml

```toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta"

[project]
name = "ipanon"
version = "0.3.0"
description = "CIDR-aware IP anonymizer with prefix-preserving permutation"
requires-python = ">=3.9"
license = "MIT"
authors = [{name = "Manon Goo", email = "manon.goo@dg-i.net"}]
readme = "README.md"
keywords = ["anonymization", "ip", "privacy", "cidr", "log-sanitization"]
classifiers = [
    "Development Status :: 4 - Beta",
    "Programming Language :: Python :: 3.9",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: System :: Networking",
    "Topic :: Utilities",
]

[project.urls]
Homepage = "https://github.com/dg-i/ipanon"
Repository = "https://github.com/dg-i/ipanon"
Issues = "https://github.com/dg-i/ipanon/issues"
Documentation = "https://github.com/dg-i/ipanon/blob/main/API.md"

[project.scripts]
ipanon = "ipanon.cli:main"

[tool.setuptools.packages.find]
where = ["src"]

[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.mypy]
python_version = "3.9"
strict = true
warn_return_any = true
warn_unused_configs = true

[tool.ruff]
line-length = 99

[tool.ruff.lint]
select = ["E", "F", "W", "I"]
```

### 1.3 .gitignore

```
__pycache__/
*.pyc
*.egg-info/
.pytest_cache/
.venv/
.claude/
dist/
build/
*.egg
uv.lock
plan.txt
```

### 1.4 Dependencies

- Python >= 3.9
- No third-party runtime dependencies (uses only stdlib: `ipaddress`, `hmac`, `hashlib`, `argparse`, `json`, `os`, `sys`, `re`, `enum`, `dataclasses`)
- Dev: `pytest`, `ruff`

### 1.5 Commands

```bash
uv venv && uv pip install -e .    # install
uv pip install pytest ruff         # dev deps
pytest tests/                      # run tests
ruff check src/ tests/             # lint
ruff format src/ tests/            # format
```

### 1.6 __init__.py

```python
"""CIDR-aware IP anonymizer with prefix-preserving permutation."""

__version__ = "0.3.0"

from ipanon.anonymizer import Anonymizer, PassThroughCollisionError
from ipanon.networks import NetworkEntry, NetworkRegistry
from ipanon.ranges import Category, classify_ip
from ipanon.scanner import find_ips, scan_and_replace

__all__ = [
    "Anonymizer",
    "Category",
    "NetworkEntry",
    "NetworkRegistry",
    "PassThroughCollisionError",
    "classify_ip",
    "find_ips",
    "scan_and_replace",
]
```

---

## 2. Problem Statement

Network configuration anonymizers like Netconan treat IPs as flat 32-bit values,
producing invalid CIDR like `10.1.237.0/8` (host bits set under the prefix).
ipanon is a CIDR-aware anonymizer with prefix-preserving permutation that
guarantees:

1. **Valid CIDR output** — network prefixes have host bits zeroed; host addresses preserve all bits with `/prefix` appended
2. **Category preservation** — private IPs stay private, public stays public, reserved unchanged
3. **Prefix preservation** — two IPs sharing a /N prefix will produce outputs sharing a /N prefix
4. **Bijectivity** — distinct inputs produce distinct outputs (no collisions)
5. **Determinism** — same salt + same input = same output, always

---

## 3. IP Classification (ranges.py)

Every IP address is classified into exactly one of three categories:

### 3.1 Category Enum

```python
class Category(Enum):
    RANGE_PRESERVED = auto()  # Category A
    PASS_THROUGH = auto()     # Category B
    PUBLIC = auto()            # Category C
```

### 3.2 Category A — Range-Preserved (IPv4)

Lock the range's prefix bits, anonymize the rest. Uses a `RangeEntry(network, locked_bits)` named tuple.

| Network | Locked Bits | Anonymized Bits | Purpose |
|---|---|---|---|
| `10.0.0.0/8` | 8 | 24 | RFC 1918 Private |
| `172.16.0.0/12` | 12 | 20 | RFC 1918 Private |
| `192.168.0.0/16` | 16 | 16 | RFC 1918 Private |
| `100.64.0.0/10` | 10 | 22 | RFC 6598 CGNAT |
| `169.254.0.0/16` | 16 | 16 | RFC 3927 Link-Local |

### 3.3 Category A — Range-Preserved (IPv6)

| Network | Locked Bits | Purpose |
|---|---|---|
| `fc00::/7` | 7 | ULA |
| `fe80::/10` | 10 | Link-Local |

### 3.4 Category B — Pass-Through (IPv4)

Returned unchanged. No anonymization.

| Network | Purpose |
|---|---|
| `0.0.0.0/8` | "This network" |
| `127.0.0.0/8` | Loopback |
| `192.0.0.0/24` | IETF Protocol Assignments |
| `192.0.2.0/24` | TEST-NET-1 |
| `198.18.0.0/15` | Benchmarking |
| `198.51.100.0/24` | TEST-NET-2 |
| `203.0.113.0/24` | TEST-NET-3 |
| `224.0.0.0/4` | Multicast |
| `240.0.0.0/4` | Reserved |
| `255.255.255.255/32` | Broadcast |

### 3.5 Category B — Pass-Through (IPv6)

`0000::/8` and `0100::/8` are broad special-use ranges that subsume several
more specific entries (`::/128`, `::1/128`, `::ffff:0:0/96`, `64:ff9b::/96`,
`100::/64`). All are listed for documentation clarity; order doesn't matter
since they're all Cat B.

| Network | Purpose |
|---|---|
| `0000::/8` | Special-use (subsumes unspecified, loopback, IPv4-mapped, etc.) |
| `0100::/8` | Special-use (subsumes discard-only, NAT64 well-known prefix, etc.) |
| `::/128` | Unspecified (subsumed by 0000::/8) |
| `::1/128` | Loopback (subsumed by 0000::/8) |
| `::ffff:0:0/96` | IPv4-mapped (subsumed by 0000::/8) |
| `64:ff9b::/96` | NAT64 (subsumed by 0100::/8) |
| `100::/64` | Discard-only (subsumed by 0100::/8) |
| `ff00::/8` | Multicast |

### 3.6 Dynamic Set Computation

Two functions in `ranges.py` compute first-octet/byte classification dynamically
from arbitrary Cat A/B lists, enabling `--ignore-subnets` and `--ignore-reserved`:

```
compute_ipv4_octet_sets(cat_a_entries, cat_b_entries) -> (reserved, mixed, pure_public)
compute_ipv6_first_byte_sets(cat_a_entries, cat_b_entries) -> (reserved, pure_public)
```

For IPv4, each entry's network is analyzed: `prefixlen <= 8` → covers entire /8(s) → reserved;
`prefixlen > 8` → partial overlap → mixed. `pure_public = {0..255} - reserved - mixed`.

For IPv6, all Cat A/B entries contribute to `reserved`; `pure_public = {0..255} - reserved`.

With default lists, these produce results identical to the static constants.

### 3.7 classify_ip() Function

```
classify_ip(addr: IPv4Address | IPv6Address) -> (Category, locked_bits)
```

- Check Category B first (for IPv4, the more specific ranges like 192.0.2.0/24 must be checked before Category A's broader 192.168.0.0/16, but since B is checked entirely before A, order within B doesn't matter for correctness)
- Then check Category A
- Default: Category C (public), locked_bits=0
- For Category B: locked_bits = 32 (IPv4) or 128 (IPv6) — meaning ALL bits are locked
- For Category C: locked_bits = 0

### 3.7 is_in_forbidden_range()

Checks if an address falls in any Category A or B range. Used to verify that
anonymized Cat C IPs don't accidentally land in reserved space.

### 3.8 IPv4 First-Octet Classification

The 256 possible first octets partition into three disjoint sets:

**RESERVED_FIRST_OCTETS_V4** (35 values): `{0, 10, 127} | {224..255}`
- These /8 blocks contain ONLY Cat A or Cat B addresses (no public IPs at all)

**MIXED_FIRST_OCTETS_V4** (6 values): `{100, 169, 172, 192, 198, 203}`
- These /8 blocks contain BOTH reserved sub-ranges AND public IPs

**PURE_PUBLIC_FIRST_OCTETS_V4** (215 values): `{0..255} - RESERVED - MIXED`
- These /8 blocks are entirely routable public addresses

These sets must:
- Be pairwise disjoint
- Union to exactly `{0..255}`
- Have sizes 35, 6, 215 respectively

### 3.9 IPv6 First-Byte Classification

**IPV6_PASS_THROUGH_FIRST_BYTES**: `{0x00, 0x01}` — special-use
**IPV6_CAT_A_FIRST_BYTES**: `{0xFC, 0xFD, 0xFE}` — ULA + link-local
**IPV6_CAT_B_FIRST_BYTES**: `{0xFF}` — multicast
**IPV6_PURE_PUBLIC_FIRST_BYTES** (250 values): everything else

These four sets must partition `{0x00..0xFF}`.

---

## 4. Permutation Algorithms (permutation.py)

### 4.1 _keyed_random_int(salt, context, index, modulus) -> int

Internal helper. Derives a deterministic random integer in `[0, modulus)`:

```python
key = salt.encode("utf-8")
msg = f"{context}:{index}".encode("utf-8")
digest = hmac.new(key, msg, hashlib.sha256).digest()
value = int.from_bytes(digest[:8], "big")  # first 8 bytes as uint64
return value % modulus
```

### 4.2 make_permutation(values, salt, context) -> Dict[int, int]

Fisher-Yates shuffle with keyed randomness. Creates a bijective mapping.

```python
arr = list(values)
n = len(arr)
for i in range(n - 1, 0, -1):
    j = _keyed_random_int(salt, context, i, i + 1)
    arr[i], arr[j] = arr[j], arr[i]
return dict(zip(values, arr))
```

**Properties:**
- Bijective: every output value appears exactly once
- Deterministic: same (values, salt, context) → same permutation
- Different salt or context → different permutation
- Single element → maps to itself

### 4.3 prefix_preserving_permute(value, num_bits, salt, context) -> int

HMAC-based bit-by-bit permutation that preserves shared prefixes.

For each bit position `i` (0 = most significant within the num_bits range):

1. Extract the prefix of original bits `[0..i)` (the bits before position i)
2. Compute: `HMAC-SHA256(key=salt, msg="{context}:{i}:{prefix_binary_string}")`
3. Take `flip = digest[0] & 1` (LSB of first byte)
4. `new_bit = original_bit[i] XOR flip`

```python
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

    orig_bit = (value >> (num_bits - 1 - i)) & 1
    new_bit = orig_bit ^ flip
    result = (result << 1) | new_bit

return result
```

**Key property — prefix preservation:** Two values sharing their top K bits
will produce outputs also sharing their top K bits. This is because the flip
decision for bit position i only depends on the prefix bits `[0..i)`, which
are identical for both values when `i < K`.

**Properties:**
- Bijective within the N-bit space (XOR with deterministic function)
- Deterministic
- Output is always in `[0, 2^num_bits)`
- 0 bits → returns 0

---

## 5. Anonymizer Engine (anonymizer.py)

### 5.1 Anonymizer Class

```python
class Anonymizer:
    def __init__(
        self,
        salt: str | None = None,
        remaps: dict[int, int] | None = None,
        pass_through_prefixes: list[str] | None = None,
        allow_pt_collisions: bool = False,
        quiet: bool = False,
        verbose: bool = False,
        ignore_subnets: bool = False,
        ignore_reserved: bool = False,
        network_registry: NetworkRegistry | None = None,
    )
```

**Constructor behavior:**
1. If salt is None, generate random salt via `os.urandom(16).hex()` and print `"Generated salt: {salt}"` to stderr (unless `quiet=True`)
2. **Filter Cat A/B lists based on flags:**
   - `ignore_reserved=True`: all four lists (Cat A v4/v6, Cat B v4/v6) become empty
   - `ignore_subnets=True`: Cat A v4 filtered to entries with `locked_bits == 8` only; Cat A v6, Cat B v4/v6 unchanged
   - Default: all lists unchanged
3. **Compute dynamic first-octet/byte sets** using `compute_ipv4_octet_sets()` and `compute_ipv6_first_byte_sets()` from the filtered lists
4. Parse pass-through prefixes with `ipaddress.ip_network(s, strict=False)`.
   For prefixes with `prefixlen == 8`, extract the affected first-octet (IPv4) or
   first-byte (IPv6) if it is in the pure-public set → `pt_excluded_octets` / `pt_excluded_bytes`
3. Validate remaps:
   - Each source must be in MIXED_FIRST_OCTETS_V4 → ValueError with "mixed" in message if not
   - Each target must be in PURE_PUBLIC_FIRST_OCTETS_V4 → ValueError with "pure-public" in message if not
   - Each target must not be in `pt_excluded_octets` → ValueError with "conflicts with" in message if so
4. Build IPv4 first-octet permutation pool: `sorted(PURE_PUBLIC_FIRST_OCTETS_V4 - remap_targets - pt_excluded_octets)`
   - Call `make_permutation(pool, salt, "v4:first_octet")`
5. Build IPv6 first-byte permutation: `sorted(IPV6_PURE_PUBLIC_FIRST_BYTES - pt_excluded_bytes)`
   - Call `make_permutation(v6_pool, salt, "v6:first_byte")`
6. Initialize empty cache `Dict[str, str]` and warned-mixed set

### 5.2 anonymize(addr_str) -> str

Main entry point. Accepts strings like `"8.8.8.8"`, `"10.0.0.0/24"`, `"2001:db8::1/32"`.

1. Check cache first — return cached result if found
2. Call `_anonymize_impl()`, cache result, return

### 5.3 Decision Flow (_anonymize_impl)

```
Parse addr_str → (ip_part, prefix_len or None)
Parse ip_part with ipaddress.ip_address()
  → If invalid: return addr_str unchanged

Resolve host_boundary from network_registry:
  If network_registry is not None:
    host_boundary = network_registry.lookup(ip_part)
  Else:
    host_boundary = None

Short prefix check (BEFORE classification):
  IPv4: /0 or /1 → return unchanged (no warning)
  IPv4: /2 to /7 → return unchanged + WARNING (verbose only)
  IPv6: /0 or /1 → return unchanged (no warning)
  IPv6: /2 to /31 → return unchanged + WARNING (verbose only)

User pass-through check:
  If addr matches any --pass-through prefix → return unchanged

Category classification via classify_ip():
  Cat B → return unchanged
  Cat A → _anonymize_cat_a(host_boundary)
  Cat C → _anonymize_cat_c(host_boundary)
```

### 5.4 Category A Algorithm (_anonymize_cat_a)

```python
int_val = int(addr)
remaining_bits = total_bits - locked_bits
locked_mask = ((1 << locked_bits) - 1) << remaining_bits
locked_part = int_val & locked_mask
host_val = int_val & ((1 << remaining_bits) - 1)

# Context uses the network string (e.g., "10.0.0.0/8")
range_name = str(matching_range.network)
context = f"v4:catA:{range_name}" or f"v6:catA:{range_name}"

# Host-bit locking: only permute network portion, preserve host portion
if host_boundary is not None and locked_bits < host_boundary < total_bits:
    net_bits = host_boundary - locked_bits
    host_bits = total_bits - host_boundary
    net_part = host_val >> host_bits
    host_part = host_val & ((1 << host_bits) - 1)
    anon_net_part = prefix_preserving_permute(net_part, net_bits, salt, context)
    anon_host = (anon_net_part << host_bits) | host_part
else:
    anon_host = prefix_preserving_permute(host_val, remaining_bits, salt, context)

anon_int = locked_part | anon_host

# CIDR masking: only when input is a network address (host bits all zero)
if prefix_len is not None:
    host_mask = (1 << (total_bits - prefix_len)) - 1
    if (int_val & host_mask) == 0:        # Network address → zero host bits in output
        anon_int &= ((1 << total_bits) - 1) ^ host_mask
    # else: host address → keep full anonymized IP, just append /prefix

# Format result
return f"{IPv4Address(anon_int)}/{prefix_len}" or f"{IPv4Address(anon_int)}"
```

**Host-bit-aware CIDR masking:** The masking behavior depends on whether the
input has host bits set:
- **Network address** (host bits all zero, e.g., `10.1.2.0/24`): output host
  bits are zeroed. This preserves valid CIDR network notation.
- **Host address** (host bits non-zero, e.g., `10.1.2.3/24`): output is the
  full anonymized IP with `/prefix` appended. This preserves interface-style
  notation like `ip address 10.1.2.3/24`.
- **Consistency**: both cases use the same underlying permutation, so the
  network portion of the host output always matches the network-only output.

**Edge case:** When `prefix_len == locked_bits` (e.g., `10.0.0.0/8` or
`172.16.0.0/12`), all anonymizable bits get masked to zero, so output equals
input. This is correct behavior.

### 5.5 Category C Algorithm — IPv4 (_anonymize_cat_c_v4)

**Step 1: Map first octet**
```python
first_octet = (int_val >> 24) & 0xFF

if first_octet in v4_first_octet_perm:
    anon_first_octet = v4_first_octet_perm[first_octet]
elif first_octet in remap_table:
    anon_first_octet = remap_table[first_octet]
else:
    # Mixed octet without remap — warn ONCE per mixed octet, pass through
    warn("WARNING: Public IP {addr} has mixed first-octet {first_octet}. "
         "Use --remap {first_octet}=<target> for collision-free anonymization.")
    anon_first_octet = first_octet
```

**Step 2: Permute bits 8-31**
```python
lower_24 = int_val & 0xFFFFFF

# Host-bit locking: only permute network portion, preserve host portion
if host_boundary is not None and 8 < host_boundary < 32:
    net_bits = host_boundary - 8
    host_bits_count = 32 - host_boundary
    net_part = lower_24 >> host_bits_count
    host_part = lower_24 & ((1 << host_bits_count) - 1)
    anon_net = prefix_preserving_permute(net_part, net_bits, salt, f"v4:{first_octet}")
    anon_lower = (anon_net << host_bits_count) | host_part
else:
    anon_lower = prefix_preserving_permute(lower_24, 24, salt, f"v4:{first_octet}")
```

Note: context uses `original_first_octet` (not anonymized), so each source /8
gets an independent permutation.

**Step 3: Assemble and mask**
```python
anon_int = (anon_first_octet << 24) | anon_lower

# CIDR masking: only when input is a network address (host bits all zero)
if prefix_len is not None:
    host_mask = (1 << (32 - prefix_len)) - 1
    if (int_val & host_mask) == 0:
        anon_int &= 0xFFFFFFFF ^ host_mask
```

**Step 4: Check pass-through collisions** (see §5.7)

### 5.6 Category C Algorithm — IPv6 (_anonymize_cat_c_v6)

Same structure but with first byte (bits 0-7) and 120-bit permutation:

```python
first_byte = (int_val >> 120) & 0xFF
anon_first_byte = v6_first_byte_perm.get(first_byte, first_byte)

lower_120 = int_val & ((1 << 120) - 1)

# Host-bit locking: only permute network portion, preserve host portion
if host_boundary is not None and 8 < host_boundary < 128:
    net_bits = host_boundary - 8
    host_bits_count = 128 - host_boundary
    net_part = lower_120 >> host_bits_count
    host_part = lower_120 & ((1 << host_bits_count) - 1)
    anon_net = prefix_preserving_permute(net_part, net_bits, salt, f"v6:{first_byte}")
    anon_lower = (anon_net << host_bits_count) | host_part
else:
    anon_lower = prefix_preserving_permute(lower_120, 120, salt, f"v6:{first_byte}")

anon_int = (anon_first_byte << 120) | anon_lower
# Host-bit-aware CIDR mask and collision check same as IPv4
```

### 5.7 Pass-Through Collision Handling

Two-tier strategy based on pass-through prefix breadth:

**Tier 1: /8 prefixes → Pool exclusion (guaranteed collision-free)**

When a `--pass-through` prefix is exactly /8, the affected first-octet (IPv4)
or first-byte (IPv6) is excluded from the permutation pool before it is built.
This reuses the same exclusion mechanism used for `--remap` targets.

Only pure-public octets/bytes are excluded. Pass-through /8 prefixes in Cat A/B
space (e.g., `10.0.0.0/8`) have no effect on the pool since those octets are
already reserved and not in the pool.

Remap targets must not conflict with excluded pass-through octets. If
`--remap 172=42` and `--pass-through 42.0.0.0/8` are both specified, a
`ValueError` is raised.

**Tier 2: Narrower-than-/8 prefixes → Post-hoc detection**

After anonymizing a Cat C IP, check if the result falls in any user-defined
`--pass-through` prefix:

- If `allow_pt_collisions=False`: raise `PassThroughCollisionError`
- If `allow_pt_collisions=True`: print WARNING to stderr, return the colliding result

For /8 prefixes, the post-hoc check serves as a safety net (should never fire
since the octet is excluded from the pool).

Error message format:
```
Anonymized IP {anon} (from {original}) collides with --pass-through prefix {net}.
Options: use --allow-pt-collisions, use a different --salt, or adjust --pass-through prefixes.
```

### 5.8 get_mapping() -> Dict[str, str]

Returns a copy of the internal cache — maps original IP strings to anonymized strings.

---

## 6. Text Scanner (scanner.py)

### 6.1 IPv4 Regex

```python
_IPV4_OCTET = r"(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
_IPV4_ADDR = rf"{_IPV4_OCTET}(?:\.{_IPV4_OCTET}){{3}}"
_IPV4_CIDR = r"(?:/(?:[0-9]|[12]\d|3[0-2]))?"
_IPV4_PATTERN = rf"(?<!\d\.)(?<!\d)({_IPV4_ADDR})({_IPV4_CIDR})(?!\.\d)(?!\d)"
```

Key design decisions:
- **Octet validation in regex**: 0-255 only (rejects 256+)
- **CIDR range**: /0 to /32 only (rejects /33+; if /33 follows an IP, match the IP without the prefix)
- **Negative lookbehind** `(?<!\d\.)(?<!\d)`: rejects OID-like `1.2.3.4.5` (won't match `3.4.5.x` from middle of longer dotted string) and version numbers like `1.2.3`
- **Negative lookahead** `(?!\.\d)(?!\d)`: rejects trailing dotted groups

### 6.2 IPv6 Regex

**CRITICAL ordering rules** for the alternation:

1. Patterns with **more groups after `::`** must come before those with fewer.
   Otherwise `2001:db8::0:0` matches as just `2001:db8::0`, leaving a stray
   `:0` that produces an invalid 9-group address after replacement.
2. Patterns with groups after `::` must come before patterns ending with bare
   `::`. Otherwise `2001:db8::1` matches as `2001:db8::` and the `1` is lost.

```python
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
    # Compressed forms ending with :: (no groups after) — MUST be after the above
    rf"|(?:{_HEX4}:){{1,7}}:"
    # ::ffff:1.2.3.4 (IPv4-mapped IPv6)
    r"|::(?:[fF]{4}:)?(?:25[0-5]|2[0-4]\d|[01]?\d\d?)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)){3}"
    r"|::"  # :: alone — last
    r")"
    r"(?:/(?:1[0-2]\d|[1-9]\d?|0))?"  # optional /0 to /128
)
```

### 6.3 Combined Pattern

```python
_COMBINED_PATTERN = re.compile(
    rf"(?:{_IPV6_PATTERN}|{_IPV4_PATTERN})",
    re.IGNORECASE,
)
```

IPv6 is tried first (to prevent IPv4 from matching IPv4-mapped addresses).

### 6.4 extract_cidrs(text) -> List[str]

Extract all CIDR strings (addr/prefix) from text. Used by
`NetworkRegistry.load_from_text()` for `--networks auto`.

```python
def extract_cidrs(text: str) -> List[str]:
    return [m.group(0) for m in find_ips(text) if "/" in m.group(0)]
```

### 6.5 find_ips(text) -> List[Match]

1. Run `_COMBINED_PATTERN.finditer(text)`
2. For each match, validate with `ipaddress.ip_address(ip_part)` — reject any regex match that doesn't parse as a valid IP
3. Return list of valid Match objects

### 6.6 scan_and_replace(text, anonymizer) -> str

1. Call `find_ips(text)` to get all matches
2. Process matches **right to left** (reversed) to preserve string offsets
3. For each match: `result = text[:start] + anonymizer.anonymize(match) + text[end:]`

---

## 7. CLI Interface (cli.py)

### 7.1 Command-Line Arguments

```
ipanon [OPTIONS] [INPUT_FILE] [OUTPUT_FILE]

Options:
  -s, --salt SALT              Reproducible anonymization salt
                               (if omitted: random, printed to stderr)
  --salt-env ENVNAME           Read salt from environment variable ENVNAME.
                               Mutually exclusive with --salt.
  --remap MIXED=TARGET         Map public IPs from mixed first-octet to
                               pure-public target. Can repeat.
  --pass-through CIDR          Don't anonymize IPs matching CIDR. Can repeat.
  --allow-pt-collisions        Downgrade pass-through collision errors to warnings
  --ignore-subnets             Treat sub-/8 IPv4 Cat A ranges as public.
                               Only 10.0.0.0/8 remains range-preserved.
                               Cat B and IPv6 are unaffected.
  --ignore-reserved            Remove ALL Cat A and Cat B handling. Every IP
                               gets fully anonymized as public. Both IPv4/IPv6.
  --networks CIDRS_OR_AUTO     Comma-separated CIDRs for subnet-aware host-bit
                               locking, or 'auto' to collect from input.
                               Supports range notation (A/X-Y) and interface
                               notation. Can combine with --network-file.
  --network-file FILE          File with one CIDR per line for subnet-aware
                               host-bit locking. # comments and blank lines
                               ignored. Can combine with --networks.
  -m, --mapping FILE           Write IP mapping to FILE (JSON). Includes
                               network list when --networks/--network-file used.
  -v, --verbose                Print stats to stderr. Can repeat:
                               -v   print count of unique IPs processed
                               -vv  print all mappings (original -> anonymized) + count
  -q, --quiet                  Suppress all warnings. Only errors are printed
                               to stderr. Overrides -v/-vv.

stdin/stdout if files omitted.
```

### 7.2 --remap Parsing

Format: `MIXED=TARGET` where both are integers.
- Invalid format (no `=`, non-integer) → print error to stderr, exit 1
- Validation errors (wrong source/target) → print error to stderr, exit 1

### 7.3 Processing Pipeline

```python
def main(argv=None):
    args = parse_args(argv)

    # Resolve salt: --salt-env reads from env var, mutually exclusive with --salt
    salt = args.salt
    if args.salt_env:
        salt = os.environ.get(args.salt_env)
        if not salt:
            error(f"Environment variable {args.salt_env} is not set or empty.")

    remaps = parse_remap_flags(args.remap)

    # Read input FIRST (needed before --networks auto can collect CIDRs)
    text = read_input(args.input_file)  # file or stdin

    # Build network registry from --networks and/or --network-file
    registry = None
    if args.networks or args.network_file:
        registry = NetworkRegistry()
        if args.network_file:
            registry.load_file(args.network_file)
        if args.networks:
            if args.networks == "auto":
                registry.load_from_text(text)
            else:
                for cidr in args.networks.split(","):
                    registry.add(cidr.strip())
        if args.verbose >= 1 and not args.quiet:
            registry.warn_overlaps()

    try:
        anonymizer = Anonymizer(
            salt=salt,
            remaps=remaps or None,
            pass_through_prefixes=args.pass_through or None,
            allow_pt_collisions=args.allow_pt_collisions,
            quiet=args.quiet,
            ignore_subnets=args.ignore_subnets,
            ignore_reserved=args.ignore_reserved,
            network_registry=registry,
        )
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    try:
        output = scan_and_replace(text, anonymizer)
    except PassThroughCollisionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    write_output(output, args.output_file)  # file or stdout

    # Write mapping — includes network list when registry is active
    if args.mapping:
        mapping = anonymizer.get_mapping()
        if registry is not None:
            mapping_data = {"networks": registry.to_spec_list(), "mapping": mapping}
        else:
            mapping_data = mapping
        json.dump(mapping_data, open(args.mapping, "w"), indent=2, sort_keys=True)

    # Verbose output (suppressed by --quiet)
    if not args.quiet:
        if args.verbose >= 2:
            for original, anonymized in sorted(anonymizer.get_mapping().items()):
                print(f"{original} -> {anonymized}", file=sys.stderr)
            print(f"Processed {len(anonymizer.get_mapping())} unique IPs.",
                  file=sys.stderr)
        elif args.verbose >= 1:
            print(f"Processed {len(anonymizer.get_mapping())} unique IPs.",
                  file=sys.stderr)
```

### 7.4 Entry Point

`pyproject.toml` defines: `ipanon = "ipanon.cli:main"`

Can also be run as: `python -m ipanon.cli`
Requires `if __name__ == "__main__": main()` at bottom of cli.py.

---

## 8. Mixed First-Octet Remapping

### 8.1 The Problem

Six first-octets (100, 169, 172, 192, 198, 203) contain both reserved
sub-ranges and public IPs. Public IPs from these octets can't participate
in the 215-value pure-public permutation (that would make it 221→215, not bijective).

### 8.2 The Solution

User specifies `--remap 172=42` meaning: public IPs with first-octet 172
get mapped to first-octet 42. The target (42) is excluded from the
pure-public permutation pool.

### 8.3 Validation Rules

1. Source must be a mixed first-octet: `{100, 169, 172, 192, 198, 203}`
2. Target must be a pure-public first-octet (not reserved, not mixed)
3. If public IP from mixed octet found without remap → WARNING to stderr (once per octet):
   `"WARNING: Public IP {addr} has mixed first-octet {octet}. Use --remap {octet}=<target>..."`

### 8.4 Collision-Freedom Proof

With K remap targets:
- (215 - K) pure-public sources → bijection → (215 - K) pool targets
- K mixed sources → 1-to-1 → K dedicated remap targets
- Target sets are disjoint
- Within each target /8: single source → 24-bit prefix-preserving bijection
- **Result: zero collisions, mathematically guaranteed**

---

## 9. Short-Prefix Handling

### 9.1 Rationale

The first-octet permutation works at the /8 boundary. CIDR prefixes shorter
than /8 span multiple first-octet blocks, so they can't be anonymized.

### 9.2 IPv4 Rules

| Prefix Length | Behavior |
|---|---|
| /0 | Pass through, no warning (default route) |
| /1 | Pass through, no warning (split default) |
| /2 to /7 | Pass through, WARNING only with `-v` |
| /8+ | Normal anonymization |

### 9.3 IPv6 Rules

| Prefix Length | Behavior |
|---|---|
| /0 | Pass through, no warning |
| /1 | Pass through, no warning |
| /2 to /31 | Pass through, WARNING only with `-v` |
| /32+ | Normal anonymization |

### 9.4 Warning Format (verbose only)

These warnings are only emitted when `verbose=True` (CLI: `-v` or `-vv`).

```
WARNING: Cannot anonymize short prefix {addr_str} (prefix length < /8). Passing through unchanged.
WARNING: Cannot anonymize short prefix {addr_str} (prefix length < /32). Passing through unchanged.
```

---

## 10. Edge Cases

| Case | Handling |
|---|---|
| Network address with /prefix (e.g., `10.1.2.0/24`) | Host bits all zero → output host bits zeroed (network address output) |
| Host address with /prefix (e.g., `10.1.2.3/24`) | Host bits non-zero → full anonymized IP with `/prefix` appended (same IP as bare) |
| Same IP, different masks (e.g., `10.1.2.3` and `10.1.2.3/24`) | Same base anonymization; host address keeps full IP, network address gets masked |
| Bare IP (no /prefix) | Full anonymization, no masking, no `/` in output |
| IPv4-mapped IPv6 (`::ffff:x.x.x.x`) | Cat B pass-through |
| Version numbers (`1.2.3`) | Rejected: regex requires exactly 4 octets |
| OIDs (`1.2.3.4.5`) | Rejected: negative lookahead `(?!\.\d)` |
| Octets > 255 (`256.0.0.1`) | Rejected by octet regex |
| IPv4 CIDR > 32 (`10.0.0.0/33`) | Match IP only, not the `/33` |
| Duplicate IPs | Cache: compute once, return cached |
| Mixed-octet public without remap | Warn once per octet, fall back to first-octet unchanged |
| `prefix_len == locked_bits` (e.g., `10.0.0.0/8`) | All anonymizable bits masked to zero, output equals input (correct) |
| IP in brackets `[10.0.0.1]` | Matches the IP, not the brackets |
| IP with port `10.0.0.1:8080` | Matches the IP, not the `:8080` |
| Pass-through collision (narrow prefix) | Error (or warn with `--allow-pt-collisions`) |
| Pass-through /8 prefix | Excluded from permutation pool; guaranteed collision-free |
| Pass-through /8 in Cat A/B space (e.g., `10.0.0.0/8`) | No pool exclusion (octet not in pure-public pool) |
| Remap target conflicts with pass-through /8 exclusion | ValueError raised |
| `--ignore-subnets`: sub-/8 Cat A IPs (172.16.x, 192.168.x, etc.) | Anonymized as Cat C (public); 10.x still Cat A |
| `--ignore-subnets`: Cat B, IPv6 Cat A | Unaffected |
| `--ignore-subnets` + `--remap 172=42` | ValueError (172 no longer mixed) |
| `--ignore-reserved`: all IPs including loopback, multicast | Anonymized as Cat C (public) |
| `--ignore-reserved`: IPv6 ULA, link-local, multicast | Anonymized as Cat C (public) |
| `--ignore-reserved` + `--remap` | ValueError (no mixed octets exist) |
| `--ignore-reserved` + `--pass-through` | Pass-through still works; other IPs fully anonymized |
| Both `--ignore-subnets` + `--ignore-reserved` | Same as `--ignore-reserved` alone |
| Invalid IP string passed to anonymize() | Return unchanged |
| `--networks` with IP not in any entry | Full permutation (no host-bit locking), same as without `--networks` |
| `--networks` with IP matching entry | Host bits below boundary preserved; network bits above boundary permuted normally |
| `--networks` stability: same salt, with vs without | Network portion of output identical; only host bits differ (preserved vs permuted) |
| `--networks` + CIDR network address (e.g., `10.1.2.0/24`) | Host bits still zeroed by CIDR masking (locking preserves zero bits as zero) |
| `--networks auto` | Collects only CIDR patterns (addr/prefix) from input text |
| `host_boundary == locked_bits` (e.g., Cat A /8 with registry /8-8) | No host-bit locking effect (all bits already locked or permuted normally) |
| `host_boundary == total_bits` (e.g., /24-32) | No host-bit locking effect (zero host bits to preserve) |

---

## 11. HMAC Context Strings

Exact context strings used in HMAC operations (critical for cross-implementation compatibility):

| Operation | Context String |
|---|---|
| IPv4 first-octet permutation | `"v4:first_octet"` |
| IPv6 first-byte permutation | `"v6:first_byte"` |
| IPv4 Cat A permutation | `"v4:catA:{network}"` e.g., `"v4:catA:10.0.0.0/8"` |
| IPv6 Cat A permutation | `"v6:catA:{network}"` e.g., `"v6:catA:fc00::/7"` |
| IPv4 Cat C bits 8-31 | `"v4:{original_first_octet}"` e.g., `"v4:8"` |
| IPv6 Cat C bits 8-127 | `"v6:{original_first_byte}"` e.g., `"v6:32"` |

Within `prefix_preserving_permute`, the HMAC message format is:
`"{context}:{bit_position}:{prefix_binary_string}"`

For example, for bit position 3 with prefix bits `101`:
`"v4:8:3:101"`

---

## 12. Testing Specification

### 12.1 test_ranges.py (51 tests)

**TestFirstOctetSets (7 tests):**
- Three IPv4 sets are pairwise disjoint
- Three sets union to `{0..255}`
- PURE_PUBLIC count = 215
- MIXED count = 6
- RESERVED count = 35
- MIXED values = `{100, 169, 172, 192, 198, 203}`
- RESERVED includes 0, 10, 127, 224-255

**TestClassifyIPv4 (21 tests):**
- Cat B: 127.0.0.1 (loopback), 0.0.0.0 (this-network), 224.0.0.1 (multicast), 255.255.255.255 (broadcast), 192.0.2.1 (TEST-NET-1), 198.51.100.1 (TEST-NET-2), 203.0.113.1 (TEST-NET-3), 198.18.0.1 (benchmarking)
- Cat A: 10.1.2.3 (locked=8), 172.16.0.1 (locked=12), 192.168.1.1 (locked=16), 100.64.0.1 (locked=10), 169.254.1.1 (locked=16)
- Cat C: 8.8.8.8 (locked=0), 1.1.1.1
- Mixed-octet public portions: 172.15.0.1, 100.0.0.1, 169.0.0.1, 192.1.0.1, 198.0.0.1, 203.1.0.1 — all Cat C

**TestClassifyIPv6 (11 tests):**
- Cat B: :: (unspecified), ::1 (loopback), ff02::1 (multicast), ::ffff:192.168.1.1 (v4-mapped)
- Cat B: 0000:ffff:0:0:0::1 (in 0000::/8 special-use), 0100::1234 (in 0100::/8 special-use)
- Cat B: ::ffff:0:0:0 (in 0000::/8, distinct from ::ffff:0:0 which is IPv4-mapped)
- Cat A: fd00::1 (ULA, locked=7), fe80::1 (link-local, locked=10)
- Cat C: 2001:db8::1, 2001:4860:4860::8888

**TestIPv6FirstByteClassification (5 tests):**
- Pass-through bytes include 0x00, 0x01
- Cat A bytes include 0xFC, 0xFD, 0xFE
- Cat B bytes include 0xFF
- Pure public = 250 values, includes 0x20
- All four sets cover {0..255}

**TestComputeIPv4OctetSets (4 tests):**
- Default lists produce same sets as static constants
- Only-/8 Cat A → 172, 100, 169 become pure-public; 192, 198, 203 stay mixed (Cat B sub-ranges)
- Empty lists → all 256 pure-public
- Any combination produces a valid partition of {0..255}

**TestComputeIPv6FirstByteSets (3 tests):**
- Default lists match static constants (250 pure-public)
- Empty lists → all 256 pure-public
- Any combination produces a valid partition of {0..255}

### 12.2 test_permutation.py (16 tests)

**TestMakePermutation (7 tests):**
- Bijection for 10 values
- Bijection for 215 values
- Deterministic (same inputs → same output)
- Different salt → different result
- Different context → different result
- Not identity (with 50 elements)
- Single element maps to itself

**TestPrefixPreservingPermute (9 tests):**
- Deterministic
- Different salt → different result
- Output within range for various inputs
- Full bijection: all 256 8-bit values → 256 distinct outputs
- Prefix preservation: values sharing top 15 bits → outputs share top 15 bits
- Different top bit → different output top bit
- 0 bits → returns 0
- 1 bit → returns 0 or 1
- 1000 random 16-bit values all produce distinct outputs

### 12.3 test_anonymizer.py (101 tests)

**TestAnonymizerBasic (3 tests):**
- Deterministic with same salt
- Different salt → different result
- Returns valid IPv4 string

**TestCategoryB (10 tests):**
- Each Cat B address unchanged: 127.0.0.1, 255.255.255.255, 224.0.0.1, 0.0.0.0, 192.0.2.1, 198.51.100.1, 203.0.113.1, 198.18.0.1, ::1, ff02::1

**TestCategoryA (10 tests):**
- Each range stays within its network: 10.x, 172.16.x, 192.168.x, 100.64.x, 169.254.x
- Cat A IPs actually change (not pass-through)
- Deterministic
- Bijection: 256 IPs in 10.0.0.x → 256 distinct outputs
- IPv6 ULA stays in fc00::/7
- IPv6 link-local stays in fe80::/10

**TestCategoryC (6 tests):**
- Public IP changes
- Public IP doesn't land in forbidden range
- Result first octet is in PURE_PUBLIC set
- 100 distinct IPs → 100 distinct outputs
- IPv6 public changes
- IPv6 public stays public

**TestCIDR (11 tests):**
- Network address Cat A (`10.1.2.0/24`): host bits zeroed in output
- Network address Cat C (`8.8.8.0/24`): host bits zeroed in output
- Network address IPv6 (`fd00::/64`): low 64 bits zeroed in output
- Host address Cat A (`10.1.2.3/24`): output IP matches bare anonymization
- Host address Cat C (`8.8.8.8/24`): output IP matches bare anonymization
- Host address IPv6 (`fd00::1/64`): output IP matches bare anonymization
- Host address point-to-point (`93.94.135.215/31`): host bit preserved
- Consistency Cat A: network output = masked host output
- Consistency Cat C: network output = masked host output
- Prefix length preserved
- Bare IP has no `/`

**TestRemap (6 tests):**
- Remap changes first octet to target
- Remap target excluded from pool (no pure-public IP gets that first octet)
- Remap is deterministic
- ValueError on reserved target (match "pure-public")
- ValueError on mixed target (match "pure-public")
- ValueError on pure-public source (match "mixed")

**TestShortPrefix (6 tests):**
- IPv4 /0 unchanged
- IPv4 /1 unchanged (both 0.0.0.0/1 and 128.0.0.0/1)
- IPv4 /2 unchanged + warning with verbose
- IPv4 /2 unchanged, no warning by default
- IPv6 /0 unchanged
- IPv6 /16 unchanged + warning with verbose

**TestPassThrough (9 tests):**
- Matching IP unchanged
- Non-matching IP anonymized
- (Collision test — placeholder)
- (Allow-collisions test — placeholder)
- /8 pass-through excludes octet from pool (pool size reduced, octet absent from keys and values)
- Narrower-than-/8 pass-through does not modify pool (no error, normal anonymization)
- Cat A/B /8 pass-through does not exclude pure-public octets (pool size unchanged)
- Remap target conflicting with /8 pass-through raises ValueError
- IPv6 /8 pass-through excludes first-byte from pool

**TestCache (2 tests):**
- Same IP returns same result
- Same IP with different mask: host address keeps full IP (matches bare)

**TestMixedOctetWarning (2 tests):**
- Warns on mixed octet without remap (stderr contains "mixed first-octet" or "remap")
- No warning with remap

**TestQuiet (4 tests):**
- Quiet suppresses "Generated salt" message
- Quiet suppresses short-prefix warning
- Quiet suppresses mixed-octet warning
- Quiet does not suppress errors (ValueError still raised)

**TestIgnoreSubnets (9 tests):**
- 172.16.0.1 fully anonymized (no longer range-preserved)
- 192.168.1.1 fully anonymized
- 100.64.0.1 fully anonymized
- 169.254.1.1 fully anonymized
- 10.1.2.3 still stays in 10.0.0.0/8 (Cat A /8 unaffected)
- 127.0.0.1 still pass-through (Cat B unaffected)
- fe80::1 still range-preserved (IPv6 Cat A unaffected)
- Pool size increases from 215 to 218 (172, 100, 169 move to pure-public)
- `--remap 172=42` raises ValueError (172 no longer mixed)

**TestIgnoreReserved (11 tests):**
- 127.0.0.1 anonymized (no longer Cat B)
- 10.1.2.3 fully anonymized (no longer Cat A)
- 224.0.0.1 anonymized (no longer Cat B)
- Pool size = 256 (all first octets pure-public)
- No mixed octets exist
- fd00::1 anonymized (IPv6 ULA no longer Cat A)
- ::1 anonymized (IPv6 loopback no longer Cat B)
- ff02::1 anonymized (IPv6 multicast no longer Cat B)
- Any remap fails (no mixed octets)
- Both flags same as --ignore-reserved alone
- --pass-through still works with --ignore-reserved

**TestHostBitLocking (12 tests):**
- CIDR input matching registry preserves host bits (last octet = 65 for `10.1.2.65/29`)
- Bare IP matching registry preserves host bits
- Without registry, all bits permuted (backwards compat)
- Network portion identical with and without registry (stability property)
- Host address never becomes broadcast with registry
- Network address stays network address (last octet = 0)
- CIDR suffix preserved in output
- IP not in registry gets full permutation (matches no-registry output)
- Cat A with registry: stays in range AND host bits preserved
- IPv6 with registry: last 64 bits (interface ID) preserved
- Plain CIDR in registry locks at its own prefix length
- Mixed v4/v6 registry: IPv4 host bits and IPv6 interface ID both preserved

### 12.4 test_scanner.py (36 tests)

**TestFindIPv4 (16 tests):**

- Simple IP found
- IP with CIDR found (e.g., `10.0.0.0/8`)
- Multiple IPs found
- Rejects version number (`1.2.3`)
- Rejects three octets
- Rejects five octets (OID-like)
- Rejects octets > 255
- Rejects octet 256
- IP at start of line
- IP at end of line
- IP in brackets (matches IP, not brackets)
- IP with port (matches IP, not `:8080`)
- /32 CIDR accepted
- /33 rejected (match IP only, not `/33`)
- 0.0.0.0/0 matched
- 255.255.255.255 matched

**TestFindIPv6 (10 tests):**
- Full form (8 groups)
- Compressed (`2001:db8::1`)
- Loopback (`::1`)
- Unspecified (`::`)
- CIDR (`2001:db8::/32`)
- Link-local (`fe80::1`)
- With prefix (`fd00::/64`)
- Multiple groups after `::` (`2001:db8::0:0/104` matched fully)
- Compressed with trailing groups (`2001:db8::f:0/112` matched fully)
- Three groups after `::` (`2001:db8::1:2:3` matched fully)

**TestScanAndReplace (10 tests):**
- Replaces IPv4 (preserves surrounding text)
- Replaces CIDR (preserves prefix length)
- Preserves non-IP text
- Replaces multiple IPs
- Deterministic
- Replaces IPv6
- Multiline (preserves newline structure)
- Cat B unchanged (127.0.0.1 stays)
- Version string preserved while IP replaced
- Compressed IPv6 with CIDR produces no extra groups (no 9-group corruption)

### 12.5 test_cli.py (41 tests)

Uses subprocess to invoke `python -m ipanon.cli`.

**TestCLIBasic (4 tests):**
- stdin/stdout: IP replaced, exit code 0
- File input/output: IP replaced, surrounding text preserved
- Deterministic with same salt
- Random salt printed to stderr

**TestCLIRemap (4 tests):**
- Remap flag works (`--remap 172=42`)
- Invalid target → non-zero exit, "pure-public" in stderr
- Invalid source → non-zero exit, "mixed" in stderr
- Bad format → non-zero exit

**TestCLIPassThrough (2 tests):**
- Single pass-through preserves matching IP
- Multiple pass-throughs all work

**TestCLIMapping (1 test):**
- `--mapping` writes JSON with input IPs as keys

**TestCLIVerbose (5 tests):**
- `-v` prints "processed" or "ips" (case-insensitive) to stderr
- `-vv` prints all mappings: each line `"{original} -> {anonymized}"` to stderr
- `-vv` also includes the stats line (processed count)
- `-v` shows short-prefix warning
- No short-prefix warning by default (without `-v`)

**TestCLIQuiet (4 tests):**
- `-q` suppresses mixed-octet warning
- `--quiet` suppresses short-prefix warning
- `-q` does not suppress errors (non-zero exit on bad remap)
- `-q` overrides `-v` (no stats output)

**TestCLISaltEnv (4 tests):**
- `--salt-env` reads salt from named env var (output matches `--salt` with same value)
- Missing env var → non-zero exit, var name in stderr
- Empty env var → non-zero exit, var name in stderr
- `--salt` and `--salt-env` mutually exclusive (argparse error)

**TestCLIIgnoreSubnets (4 tests):**
- Flag accepted (exit code 0)
- 172.16.0.1 anonymized as public
- 10.x still range-preserved
- `--remap 172=42` fails with "mixed" error

**TestCLIIgnoreReserved (4 tests):**
- Flag accepted (exit code 0)
- 127.0.0.1 anonymized
- 10.1.2.3 anonymized
- Combined with `--pass-through` still works

**TestNetworksFlag (9 tests):**
- `--networks` with inline CIDRs preserves host bits (last octet = 65)
- `--networks auto` collects CIDRs from input
- `--network-file` loads from file
- `--networks` and `--network-file` can be combined
- Verbose mode warns about overlapping networks
- Without `--networks`, output unchanged (backwards compat)
- Mapping file includes `networks` list when `--networks` used
- Mapping file is flat dict when `--networks` not used
- Invalid network spec (`/24-16`) produces error

### 12.6 test_networks.py (27 tests)

**TestNetworkEntry (4 tests):**
- Plain CIDR creates entry where network prefix == host_boundary
- Range CIDR creates entry with different match scope and host boundary
- Interface notation extracts correct network (e.g., `11.2.3.65/29` → `11.2.3.64/29`)
- Range notation with host bits in address

**TestNetworkRegistryAdd (7 tests):**
- Host boundary < match prefix raises ValueError
- Range with boundary == prefix is same as plain CIDR
- Deduplication: same network from different host addresses counted once
- IPv6 plain CIDR
- IPv6 range notation
- IPv4 boundary exceeding 32 raises ValueError
- IPv6 boundary exceeding 128 raises ValueError

**TestNetworkRegistryLookup (9 tests):**
- Basic match returns host_boundary
- No match returns None
- Empty registry returns None
- Lowest host_boundary wins among all matching entries
- Lowest host_boundary wins regardless of add order
- Non-overlapping networks match independently
- IPv6 address lookup
- Range CIDR returns host_boundary, not match prefix
- Mixed v4 and v6 entries: each protocol looks up independently

**TestNetworkRegistryLoadFile (2 tests):**
- Load networks from file (comments and blank lines ignored)
- Comments and blank lines are ignored

**TestNetworkRegistryLoadFromText (1 test):**
- Auto-collect CIDRs from config text

**TestNetworkRegistryWarnOverlaps (2 tests):**
- Overlapping networks produce a warning
- Non-overlapping networks produce no warning

**TestNetworkRegistryEntries (2 tests):**
- Export entries as spec strings (range notation preserved)
- Plain CIDR exported without range notation

---

## 13. Subnet-Aware Host-Bit Locking (networks.py)

### 13.1 Problem

The prefix-preserving permutation can map valid host addresses onto broadcast
(all host bits = 1) or network (all host bits = 0) addresses within a subnet.
Routers reject these addresses for interface assignment.

### 13.2 Solution: NetworkRegistry

A `NetworkRegistry` collects known subnets and provides lowest-host-boundary
lookup. During anonymization, the registry determines a `host_boundary` —
the bit position where host bits start. Bits above the boundary are anonymized
(shuffle + HMAC permutation); bits at and below the boundary are preserved
unchanged.

### 13.3 Network Specification Format

Two forms are supported:

- **Plain CIDR**: `10.1.2.0/24` — match scope AND host boundary are both /24
- **Range CIDR**: `10.0.0.0/8-24` — match scope is /8, host boundary is /24.
  Bits 8–23 are HMAC-permuted, bits 24–31 are preserved.

Interface notation is accepted: `11.2.3.65/29` → network `11.2.3.64/29`.

### 13.3.1 Bit-Level Walkthrough

**Example: `--networks 8.1.0.0/16-24` with input `8.1.2.3`**

The `/16` means only IPs in `8.1.0.0/16` are affected (e.g., `9.1.2.3` is
untouched). The `-24` sets the host boundary at bit 24.

```
8.1.2.3 = 00001000 . 00000001 . 00000010 . 00000011
          |--------- anonymize first 24 bits ---------|-- keep last 8 --|
          |shuffle 8|---HMAC permute 16 bits----------|-- preserve ----|
          (octet 1)   (bits 8-23)                       (bits 24-31)
```

- **Bits 0–7** (first octet `8`): shuffled via the first-octet permutation table
- **Bits 8–23** (16 bits): HMAC prefix-preserving permuted with context `v4:8`
- **Bits 24–31** (last octet `.3`): preserved unchanged

Output: `{shuffled}.{permuted}.{permuted}.3` — the `.3` survives anonymization.

**Example: `--networks 10.0.0.0/8-24` with Cat A input `10.50.100.42`**

Cat A already locks the first 8 bits (`10.`). The host boundary at 24 further
restricts the permutable window:

```
10.50.100.42 = 00001010 . 00110010 . 01100100 . 00101010
               |Cat A lock|---HMAC permute 16 bits------|-- preserve --|
               (bits 0-7)  (bits 8-23)                    (bits 24-31)
```

- **Bits 0–7**: locked by Cat A (stays `10.`)
- **Bits 8–23**: HMAC permuted with context `v4:catA:10.0.0.0/8`
- **Bits 24–31** (`.42`): preserved by host-bit locking

**Example: IPv6 `--networks 2001:db8::/32-64` with input `2001:db8:1:2:a:b:c:d`**

```
2001:db8:1:2:a:b:c:d
|shuffle 8|---HMAC permute 56 bits---|--- preserve 64 bits (IID) ---|
(byte 0)   (bits 8-63)                (bits 64-127)
```

- **Bits 0–7** (first byte `0x20`): shuffled via IPv6 first-byte permutation
- **Bits 8–63** (56 bits): HMAC prefix-preserving permuted
- **Bits 64–127** (interface identifier `a:b:c:d`): preserved unchanged

**Example: IPv6 Cat A `--networks fe80::/10-64` with link-local `fe80::1`**

```
fe80::1
|Cat A lock 10|---HMAC permute 54 bits---|--- preserve 64 bits (IID) ---|
(bits 0-9)     (bits 10-63)               (bits 64-127)
```

- **Bits 0–9**: locked by Cat A (stays in `fe80::/10`)
- **Bits 10–63** (54 bits): HMAC permuted
- **Bits 64–127** (EUI-64 interface identifier): preserved

### 13.4 Lookup Rule

**Lowest host_boundary wins.** Among all matching entries, the one with the
smallest `host_boundary` is selected (fewest bits anonymized, most host bits
preserved). This is the safest choice: it locks the most host bits.

**Example:** Given two overlapping range entries:

- `93.94.128.0/19-27` → match scope /19, host_boundary=27
- `93.94.128.0/20-24` → match scope /20, host_boundary=24

An address in `93.94.128.0/20` matches both entries. The /19 entry has
host_boundary=27 (5 host bits preserved); the /20 entry has host_boundary=24
(8 host bits preserved). The lowest host_boundary (24) wins, preserving
the most host bits.

### 13.5 Stability Property

The HMAC context string is unchanged (`v4:{first_octet}` for Cat C IPv4).
The prefix-preserving permutation produces the same bit-flip decisions for
the first N bits regardless of how many total bits are permuted. Adding
`--networks` only changes host bits (from permuted to preserved). The
network portion of the output is identical with and without `--networks`.

### 13.6 CLI Flags

- `--networks CIDRS_OR_AUTO` — comma-separated CIDRs or `auto`
- `--network-file FILE` — one CIDR per line, `#` comments, blank lines ignored
- Both can be combined (merged into one registry)
- With `-v`, overlapping (redundant) networks produce a warning

### 13.7 Mapping File

When `--mapping FILE` is used with networks, the JSON output includes the
network list:

```json
{
  "networks": ["10.0.0.0/8-24", "192.168.1.0/29"],
  "mapping": {"10.1.2.65": "149.58.91.65", ...}
}
```

Without networks, the format stays as the current flat dict.

---

## 14. Warnings and Errors Summary

All warnings and errors go to stderr. All warnings are suppressed by `-q`/`--quiet`.

| Condition | Output | Severity |
|---|---|---|
| No salt provided | `Generated salt: {hex}` | Info (stderr, suppressed by -q) |
| Short IPv4 prefix (/2-/7) | `WARNING: Cannot anonymize short prefix {addr} (prefix length < /8). Passing through unchanged.` | Verbose warning (-v only, suppressed by -q) |
| Short IPv6 prefix (/2-/31) | `WARNING: Cannot anonymize short prefix {addr} (prefix length < /32). Passing through unchanged.` | Verbose warning (-v only, suppressed by -q) |
| Mixed octet without remap | `WARNING: Public IP {addr} has mixed first-octet {oct}. Use --remap {oct}=<target>...` | Warning (once per octet) |
| Remap source not mixed | `ValueError: Remap source {n} is not a mixed first-octet. Valid mixed octets: [100, 169, 172, 192, 198, 203]` | Error (exit 1) |
| Remap target not pure-public | `ValueError: Remap target {n} is not a pure-public first-octet.` | Error (exit 1) |
| Remap target conflicts with pass-through /8 | `ValueError: Remap target {n} conflicts with --pass-through prefix...` | Error (exit 1) |
| Pass-through collision (narrow prefix) | `PassThroughCollisionError: Anonymized IP {anon} (from {orig}) collides with --pass-through prefix {net}...` | Error (exit 1) |
| Pass-through collision (allowed) | `WARNING: {same message}` | Warning |
| Bad --remap format | `ERROR: Invalid --remap format '{val}'...` | Error (exit 1) |
| --salt-env var not set or empty | `ERROR: Environment variable {name} is not set or empty.` | Error (exit 1) |
| Network overlap (verbose) | `WARNING: Network {inner} is contained in {outer} (redundant — {outer} already covers it)` | Verbose warning (-v only, suppressed by -q) |
| Invalid network spec | `ERROR: host boundary {n} must be >= match prefix {m} in '{spec}'` | Error (exit 1) |
| Invalid --network-file | `ERROR: {OSError or ValueError message}` | Error (exit 1) |
| -v (verbose) | `Processed {N} unique IPs.` | Info (stderr, suppressed by -q) |
| -vv (very verbose) | `{original} -> {anonymized}` for each mapping, then stats | Info (stderr, suppressed by -q) |
