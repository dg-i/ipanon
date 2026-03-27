# ipanon API Reference

## Module: `ipanon`

```python
import ipanon
```

### Public Exports

| Name | Type | Description |
|------|------|-------------|
| `Anonymizer` | class | Core anonymization engine |
| `Category` | enum | IP classification categories |
| `NetworkEntry` | dataclass | A network with match scope and host-bit boundary |
| `NetworkRegistry` | class | Subnet registry for host-bit locking |
| `PassThroughCollisionError` | exception | Raised on anonymized/pass-through IP collision |
| `classify_ip` | function | Classify an IP into Category A/B/C |
| `find_ips` | function | Find all IPs in a text string |
| `scan_and_replace` | function | Find and replace all IPs in text |

---

## `Anonymizer`

The core anonymization engine. Handles IP classification, permutation, remapping, caching, and pass-through logic.

### Constructor

```python
Anonymizer(
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

**Parameters:**

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `salt` | `str \| None` | `None` | Anonymization salt for deterministic output. If `None`, a random salt is generated and printed to stderr. |
| `remaps` | `dict[int, int] \| None` | `None` | Map mixed first-octets to pure-public targets. Keys must be mixed octets (e.g., `172`), values must be pure-public octets. |
| `pass_through_prefixes` | `list[str] \| None` | `None` | CIDR strings for IPs that should not be anonymized (e.g., `["10.0.0.0/8"]`). |
| `allow_pt_collisions` | `bool` | `False` | If `True`, downgrade pass-through collision errors to stderr warnings instead of raising `PassThroughCollisionError`. |
| `quiet` | `bool` | `False` | Suppress all warnings to stderr. |
| `verbose` | `bool` | `False` | Enable verbose warnings (e.g., short-prefix pass-through notices). |
| `ignore_subnets` | `bool` | `False` | Treat sub-/8 IPv4 Cat A ranges (`172.16/12`, `192.168/16`, `100.64/10`, `169.254/16`) as public. Only `10.0.0.0/8` remains range-preserved. Cat B and IPv6 are unaffected. |
| `ignore_reserved` | `bool` | `False` | Remove ALL Cat A and Cat B handling. Every IP (including loopback, multicast, private) gets fully anonymized as public. Affects both IPv4 and IPv6. |
| `network_registry` | `NetworkRegistry \| None` | `None` | If provided, enables subnet-aware host-bit locking. The registry determines which bits are permuted (network portion) and which are preserved (host portion). |

**Raises:**
- `ValueError` — if a remap source is not a mixed first-octet, a remap target is not pure-public, or a remap target conflicts with a pass-through /8 exclusion.

**Examples:**

```python
# Basic usage with auto-generated salt
anon = Anonymizer()  # prints "Generated salt: ..." to stderr

# Deterministic with fixed salt
anon = Anonymizer(salt="my-secret")

# With remapping: route 172.x public IPs to the 42.x range
anon = Anonymizer(salt="s", remaps={172: 42})

# Preserve your monitoring subnet
anon = Anonymizer(salt="s", pass_through_prefixes=["10.0.0.0/8"])

# Anonymize everything, including private/reserved ranges
anon = Anonymizer(salt="s", ignore_reserved=True)
```

### `Anonymizer.anonymize(addr_str: str) -> str`

Anonymize a single IP address or CIDR prefix string.

**Parameters:**
- `addr_str` — IP address string, optionally with CIDR prefix (e.g., `"8.8.8.8"`, `"10.0.0.0/8"`, `"2001:db8::1/32"`).

**Returns:** The anonymized IP string. CIDR prefix notation is preserved if present.

**Behavior by category:**
- **Cat A (range-preserved):** Prefix bits are locked, remaining bits are permuted. `10.1.2.3` stays in `10.0.0.0/8`.
- **Cat B (pass-through):** Returned unchanged. `127.0.0.1` → `127.0.0.1`.
- **Cat C (public):** First octet is permuted within the pure-public pool, lower 24 bits are prefix-preserving permuted.

**Special cases:**
- Invalid IP strings are returned unchanged.
- Short prefixes (`< /8` for IPv4, `< /32` for IPv6) are returned unchanged.
- Results are cached: calling `anonymize("8.8.8.8")` twice returns the same result without recomputation.

```python
anon = Anonymizer(salt="test")

anon.anonymize("8.8.8.8")           # Public → fully anonymized
anon.anonymize("10.1.2.3")          # Private → stays in 10.0.0.0/8
anon.anonymize("127.0.0.1")         # Loopback → "127.0.0.1"
anon.anonymize("192.168.1.0/24")    # CIDR preserved → "192.168.x.0/24"
anon.anonymize("2001:db8::1")       # IPv6 → fully anonymized
anon.anonymize("not-an-ip")         # Invalid → "not-an-ip"
```

### `Anonymizer.get_mapping() -> dict[str, str]`

Return the mapping of all IPs processed so far.

**Returns:** A dict mapping original IP strings to their anonymized equivalents.

```python
anon = Anonymizer(salt="test")
anon.anonymize("8.8.8.8")
anon.anonymize("10.1.2.3")
anon.get_mapping()
# {"8.8.8.8": "143.57.192.12", "10.1.2.3": "10.187.42.5"}
```

---

## `scan_and_replace(text: str, anonymizer: Anonymizer) -> str`

Scan text for all IPv4 and IPv6 addresses (with optional CIDR notation) and replace them with anonymized versions.

**Parameters:**
- `text` — Input text containing IP addresses.
- `anonymizer` — An `Anonymizer` instance.

**Returns:** Text with all detected IPs replaced.

```python
from ipanon import Anonymizer, scan_and_replace

anon = Anonymizer(salt="test")
text = "Server 8.8.8.8 rejected connection from 10.0.1.5"
result = scan_and_replace(text, anon)
# "Server 143.57.192.12 rejected connection from 10.187.42.5"
```

**Detection notes:**
- Matches both IPv4 and IPv6 addresses, including compressed forms.
- Rejects version-number-like patterns (e.g., `1.2.3.4` adjacent to other dots).
- CIDR notation (`/0` through `/32` for IPv4, `/0` through `/128` for IPv6) is detected and preserved.

---

## `find_ips(text: str) -> list[re.Match]`

Find all valid IP addresses in text without replacing them.

**Parameters:**
- `text` — Input text to scan.

**Returns:** A list of `re.Match` objects. Each match's `group(0)` is the full IP string (including optional CIDR prefix).

```python
from ipanon import find_ips

matches = find_ips("Servers: 8.8.8.8 and 2001:db8::1/48")
[m.group(0) for m in matches]
# ["8.8.8.8", "2001:db8::1/48"]
```

---

## `classify_ip(addr: IPv4Address | IPv6Address) -> tuple[Category, int]`

Classify an IP address using the default (unfiltered) range tables.

**Parameters:**
- `addr` — An `ipaddress.IPv4Address` or `ipaddress.IPv6Address` object.

**Returns:** A tuple of `(Category, locked_bits)`:
- **Category A:** `(Category.RANGE_PRESERVED, prefix_len)` — e.g., `(Category.RANGE_PRESERVED, 8)` for `10.x.x.x`
- **Category B:** `(Category.PASS_THROUGH, 32)` for IPv4, `(Category.PASS_THROUGH, 128)` for IPv6
- **Category C:** `(Category.PUBLIC, 0)`

```python
import ipaddress
from ipanon import classify_ip, Category

classify_ip(ipaddress.IPv4Address("10.1.2.3"))
# (Category.RANGE_PRESERVED, 8)

classify_ip(ipaddress.IPv4Address("127.0.0.1"))
# (Category.PASS_THROUGH, 32)

classify_ip(ipaddress.IPv4Address("8.8.8.8"))
# (Category.PUBLIC, 0)

classify_ip(ipaddress.IPv6Address("fe80::1"))
# (Category.RANGE_PRESERVED, 10)
```

---

## `Category`

Enum for IP classification categories.

| Member | Description |
|--------|-------------|
| `Category.RANGE_PRESERVED` | Category A — private/link-local ranges; prefix locked, host bits permuted |
| `Category.PASS_THROUGH` | Category B — loopback, multicast, documentation; returned unchanged |
| `Category.PUBLIC` | Category C — routable public IPs; fully anonymized |

---

## `NetworkRegistry`

Collects subnets and provides lowest-host-boundary lookup for host-bit locking.

### Constructor

```python
NetworkRegistry()
```

### Methods

| Method | Description |
|--------|-------------|
| `add(spec: str)` | Add a network spec (plain or range CIDR). Interface notation accepted. |
| `lookup(addr_str: str) -> int \| None` | Find host-bit boundary for address. Returns `None` if no match. |
| `load_file(path: str)` | Load specs from file (one per line, `#` comments, blank lines ignored). |
| `load_from_text(text: str)` | Auto-collect CIDR patterns from text. |
| `entries() -> list[NetworkEntry]` | Return all entries. |
| `to_spec_list() -> list[str]` | Export entries as spec strings. |
| `warn_overlaps()` | Print warnings to stderr for redundant overlapping networks. |

### Examples

```python
from ipanon import Anonymizer, NetworkRegistry

# Create registry with range notation
registry = NetworkRegistry()
registry.add("10.0.0.0/8-24")     # /8 scope, host boundary at /24
registry.add("192.168.1.0/29")    # /29 scope and boundary
registry.add("2001:db8::/32-64")  # IPv6

# Use with Anonymizer
anon = Anonymizer(salt="test", network_registry=registry)
anon.anonymize("10.1.2.65")  # Last octet (65) preserved
anon.anonymize("10.1.2.65/29")  # → "x.y.z.65/29"
```

---

## `NetworkEntry`

Dataclass representing a network with its match scope and host-bit boundary.

| Field | Type | Description |
|-------|------|-------------|
| `network` | `IPv4Network \| IPv6Network` | Match scope (e.g., `10.0.0.0/8`) |
| `host_boundary` | `int` | Prefix length where host bits start (e.g., `24`) |

---

## `PassThroughCollisionError`

Exception raised when an anonymized IP collides with a `--pass-through` prefix and `allow_pt_collisions` is `False`.

```python
from ipanon import Anonymizer, PassThroughCollisionError

try:
    anon = Anonymizer(salt="s", pass_through_prefixes=["8.0.0.0/8"])
    anon.anonymize("1.2.3.4")  # might collide with 8.x.x.x
except PassThroughCollisionError as e:
    print(f"Collision: {e}")
```

To downgrade collisions to warnings instead:

```python
anon = Anonymizer(salt="s", pass_through_prefixes=["8.0.0.0/8"], allow_pt_collisions=True)
```
