# ipanon

A deterministic, CIDR-aware IP anonymizer for log sanitization. Replaces IPv4 and IPv6 addresses in text while maintaining CIDR prefix relationships and respecting reserved/private range boundaries.

## Features

- **Prefix-preserving permutation** — IPs sharing a /8 or larger subnet stay grouped after anonymization; subnet relationships are preserved at every prefix length
- **Three-tier classification** — private ranges stay private, loopback/multicast pass through unchanged, public IPs get fully anonymized
- **Subnet-aware host-bit locking** — preserves host bits within known subnets, preventing broadcast/network address collisions in router configs
- **Deterministic** — same salt always produces the same output, enabling cross-log correlation
- **IPv4 + IPv6** — full support for both protocols including CIDR notation
- **Streaming** — reads stdin, writes stdout; works in pipelines
- **No dependencies** — pure Python, stdlib only

## Installation

```bash
pip install ipanon
```

Or from source:

```bash
pip install .
```

## Quick Start

```bash
# Anonymize a log file (auto-generated random salt printed to stderr)
cat access.log | ipanon > anonymized.log

# Reproducible anonymization with a fixed salt
ipanon --salt mysecret input.log output.log

# Save the IP mapping for later analysis
ipanon --salt mysecret -m mapping.json < input.log > output.log
```

## How It Works

Every IP address is classified into one of three categories:

| Category | Behavior | Examples |
|----------|----------|---------|
| **A — Range-preserved** | Prefix bits locked, remaining bits permuted. `10.x.y.z` stays in `10.0.0.0/8`, `172.16.x.y` stays in `172.16.0.0/12`, etc. | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`, `169.254.0.0/16`, `fc00::/7`, `fe80::/10` |
| **B — Pass-through** | Returned unchanged. | `127.0.0.1`, `0.0.0.0/8`, `224.0.0.0/4`, `::1`, `ff00::/8` |
| **C — Public** | First octet permuted within a safe pool, lower 24 bits prefix-preserving permuted. Two IPs in the same /8 map to the same anonymized /8. | `8.8.8.8`, `1.1.1.1`, `2001:db8::1` |

Public IPs are guaranteed never to land in Category A or B address space after anonymization.

### Mixed First-Octets

Six IPv4 first-octets (100, 169, 172, 192, 198, 203) contain both reserved sub-ranges and public IPs — for example, `172.16.0.0/12` is private but `172.217.x.x` (Google) is public. Because these octets can't safely participate in the normal first-octet permutation pool, public IPs from mixed octets keep their first octet unchanged by default (with a warning).

To get collision-free anonymization for these IPs, use `--remap` to redirect them to a dedicated pure-public octet:

```bash
# Redirect public 172.x IPs to the 42.x range
ipanon --salt s --remap 172=42 < input.log

# Redirect multiple mixed octets
ipanon --salt s --remap 172=42 --remap 192=43 < input.log
```

Alternatively, use `--ignore-subnets` to remove the sub-/8 private ranges entirely, which eliminates the mixed-octet problem by treating those IPs as fully public:

```bash
# Only 10.0.0.0/8 stays private; 172.16.x, 192.168.x, etc. treated as public
ipanon --salt s --ignore-subnets < input.log
```

## CLI Reference

```
ipanon [OPTIONS] [INPUT] [OUTPUT]
```

| Option | Description |
|--------|-------------|
| `-s`, `--salt SALT` | Reproducible anonymization salt (random if omitted, printed to stderr) |
| `--salt-env ENVNAME` | Read salt from environment variable. Mutually exclusive with `--salt` |
| `--remap MIXED=TARGET` | Redirect public IPs from a mixed first-octet to a dedicated pure-public target (see [Mixed First-Octets](#mixed-first-octets)). Can repeat |
| `--pass-through CIDR` | Don't anonymize IPs matching CIDR prefix. /8 prefixes are excluded from the permutation pool (guaranteed collision-free); narrower prefixes use post-hoc detection. Can repeat |
| `--allow-pt-collisions` | Downgrade pass-through collision errors to warnings |
| `--ignore-subnets` | Treat sub-/8 IPv4 private ranges as public. Only `10.0.0.0/8` stays range-preserved; Cat B and IPv6 are unaffected |
| `--ignore-reserved` | Remove ALL reserved range handling (Cat A and Cat B). Every IP — including loopback, multicast, private — gets fully anonymized. Affects both IPv4 and IPv6 |
| `--networks CIDRS` | Comma-separated CIDRs for subnet-aware host-bit locking (e.g., `10.0.0.0/8-24`), or `auto` to collect from input. Preserves host bits within each subnet. Supports range notation and interface notation. Can combine with `--network-file` |
| `--network-file FILE` | File with one CIDR per line for subnet-aware host-bit locking. Blank lines and `#` comments ignored. Can combine with `--networks` |
| `-m`, `--mapping FILE` | Write JSON mapping of original-to-anonymized IPs to FILE. Includes network list when `--networks`/`--network-file` used |
| `-v`, `--verbose` | Print stats to stderr. `-vv` also prints all mappings |
| `-q`, `--quiet` | Suppress all warnings. Overrides `-v`/`-vv` |

### Examples

```bash
# Don't anonymize your monitoring subnet
ipanon --salt s --pass-through 10.0.0.0/8 < input.log

# Only keep 10.0.0.0/8 private; treat 172.16.x, 192.168.x, etc. as public
ipanon --salt s --ignore-subnets < input.log

# Treat ALL IPs as public (ignore private/reserved ranges entirely)
ipanon --salt s --ignore-reserved < input.log

# Salt from environment variable
export ANON_SALT="my-secret-salt"
ipanon --salt-env ANON_SALT < input.log
```

### Subnet-Aware Host-Bit Locking

When anonymizing router configurations, the permutation can map valid host addresses onto broadcast or network addresses — which routers reject. The `--networks` flag prevents this by preserving host bits within known subnets:

```bash
# Plain CIDR: host bits within /29 are preserved
ipanon --salt s --networks 192.168.1.0/29 < router.conf

# Range notation: within the /8 block, preserve host bits at /24 boundary
# Bits 8-23 are permuted, bits 24-31 are preserved
ipanon --salt s --networks 10.0.0.0/8-24 < router.conf

# Networks file for multi-router consistency
cat > subnets.txt <<EOF
# Large blocks with /24 host boundary
10.0.0.0/8-24
172.16.0.0/12-24
# Specific small subnets
192.168.1.0/29
# IPv6
2001:db8::/32-64
EOF
ipanon --salt s --network-file subnets.txt rtrA.conf > rtrA.anon
ipanon --salt s --network-file subnets.txt rtrB.conf > rtrB.anon

# Auto-collect subnets from input (one-off convenience)
ipanon --salt s --networks auto < router.conf
```

Interface notation is accepted — `10.1.2.65/29` is interpreted as network `10.1.2.64/29`.

The network list is part of the anonymization configuration alongside the salt. For reproducible multi-device anonymization, save both the salt and the networks file.

## Use Cases

### Log Sanitization

Anonymize IP addresses in log files before sharing with vendors or publishing:

```bash
# Nginx access logs
ipanon --salt "$SECRET" < /var/log/nginx/access.log > sanitized-access.log

# Batch-process multiple log files with the same salt for cross-log correlation
for f in /var/log/app/*.log; do
    ipanon --salt "$SECRET" "$f" "sanitized/$(basename "$f")"
done

# Pipe from journald
journalctl -u myservice --no-pager | ipanon --salt "$SECRET" > sanitized.log

# Apache combined log format — structure is preserved, only IPs change
# Before: 203.0.113.50 - - [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326
# After:  71.142.89.50 - - [10/Oct/2024:13:55:36 -0700] "GET /index.html HTTP/1.1" 200 2326

# Save the mapping so you can look up the original IP if needed
ipanon --salt "$SECRET" -m mapping.json < access.log > sanitized.log
cat mapping.json
# {"203.0.113.50": "71.142.89.50", "10.0.1.5": "10.218.94.5", ...}
```

### Config File Sanitization

Scrub IP addresses from configuration files before committing or sharing:

```bash
# Sanitize firewall rules
ipanon --salt cfg < iptables-rules.txt > iptables-rules.sanitized.txt

# Sanitize network configs, keeping internal structure visible
# --pass-through keeps your well-known subnets readable
ipanon --salt cfg --pass-through 10.0.0.0/8 < network.conf > network.sanitized.conf

# Sanitize DNS zone files
ipanon --salt cfg < db.example.com > db.example.sanitized.com

# Sanitize Kubernetes manifests or Terraform state
ipanon --salt cfg < terraform.tfstate > terraform.sanitized.tfstate

# Sanitize Ansible inventories
ipanon --salt cfg < hosts.ini > hosts.sanitized.ini
```

### Sharing Diagnostic Output

Clean up diagnostic output before pasting into bug reports or support tickets:

```bash
# Sanitize traceroute output
traceroute example.com | ipanon --salt diag

# Sanitize tcpdump captures (text output)
tcpdump -nn -r capture.pcap | ipanon --salt diag > sanitized-capture.txt

# Sanitize `ss` or `netstat` output
ss -tunap | ipanon --salt diag

# Sanitize `ip addr` output
ip addr show | ipanon --salt diag
```

### CI/CD Pipelines

```bash
# Set salt once per pipeline run for consistent anonymization across steps
export ANON_SALT="$(openssl rand -hex 16)"

# Anonymize test artifacts before uploading
ipanon --salt-env ANON_SALT < test-output.log > sanitized-output.log
ipanon --salt-env ANON_SALT < network-diag.txt > sanitized-diag.txt
```

## Python API

See [API.md](API.md) for complete API documentation.

```python
from ipanon import Anonymizer, scan_and_replace

# Single IP anonymization
anon = Anonymizer(salt="mysecret")
anon.anonymize("8.8.8.8")        # → "143.57.192.12" (deterministic)
anon.anonymize("10.1.2.3")       # → "10.187.42.5" (stays in 10.0.0.0/8)
anon.anonymize("127.0.0.1")      # → "127.0.0.1" (pass-through)

# Bulk text replacement
text = "Server 8.8.8.8 connected to 10.0.1.5 via 192.168.1.1"
scan_and_replace(text, anon)
# → "Server 143.57.192.12 connected to 10.187.42.5 via 192.168.78.201"
```

## Requirements

- Python >= 3.9
- No external dependencies

## License

MIT
