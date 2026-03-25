# ipanon

A deterministic, CIDR-aware IP anonymizer for log sanitization. Replaces IPv4 and IPv6 addresses in text while maintaining CIDR prefix relationships and respecting reserved/private range boundaries.

## Features

- **Prefix-preserving permutation** — IPs sharing a subnet stay grouped after anonymization
- **Three-tier classification** — private ranges stay private, loopback/multicast pass through unchanged, public IPs get fully anonymized
- **Deterministic** — same salt always produces the same output, enabling cross-log correlation
- **IPv4 + IPv6** — full support for both protocols including CIDR notation
- **Streaming** — reads stdin, writes stdout; works in pipelines

## Installation

```bash
pip install .
```

Or with [uv](https://docs.astral.sh/uv/):

```bash
uv pip install .
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
| **A — Range-preserved** | Prefix bits locked, remaining bits permuted. `10.x.y.z` stays in `10.0.0.0/8`. | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`, `fe80::/10` |
| **B — Pass-through** | Returned unchanged. | `127.0.0.1`, `0.0.0.0/8`, `224.0.0.0/4`, `::1`, `ff00::/8` |
| **C — Public** | Fully anonymized with first-octet permutation + prefix-preserving lower bits. | `8.8.8.8`, `1.1.1.1`, `2001:db8::1` |

Public IPs are guaranteed never to land in Category A or B address space after anonymization.

## CLI Reference

```
ipanon [OPTIONS] [INPUT] [OUTPUT]
```

| Option | Description |
|--------|-------------|
| `-s`, `--salt SALT` | Reproducible anonymization salt (random if omitted) |
| `--salt-env ENVNAME` | Read salt from environment variable |
| `--remap MIXED=TARGET` | Map public IPs from a mixed first-octet to a pure-public target. Can repeat |
| `--pass-through CIDR` | Don't anonymize IPs matching CIDR prefix. Can repeat |
| `--allow-pt-collisions` | Downgrade pass-through collision errors to warnings |
| `--ignore-subnets` | Treat sub-/8 IPv4 private ranges as public (only `10.0.0.0/8` stays Cat A) |
| `--ignore-reserved` | Remove ALL reserved range handling; every IP gets fully anonymized |
| `-m`, `--mapping FILE` | Write JSON mapping of original-to-anonymized IPs to FILE |
| `-v`, `--verbose` | Print stats to stderr. `-vv` also prints all mappings |
| `-q`, `--quiet` | Suppress all warnings |

### Examples

```bash
# Remap 172.x public IPs to the 42.x range
ipanon --salt s --remap 172=42 < input.log

# Don't anonymize your monitoring subnet
ipanon --salt s --pass-through 10.0.0.0/8 < input.log

# Treat all IPs as public (ignore private/reserved ranges)
ipanon --salt s --ignore-reserved < input.log

# Salt from environment variable
export ANON_SALT="my-secret-salt"
ipanon --salt-env ANON_SALT < input.log
```

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
