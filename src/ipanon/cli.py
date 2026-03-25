"""CLI interface for ipanon: CIDR-aware IP anonymizer."""

from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict, List, Optional, Tuple

from ipanon.anonymizer import Anonymizer, PassThroughCollisionError
from ipanon.scanner import scan_and_replace


def parse_remap(value: str) -> Tuple[int, int]:
    """Parse a --remap argument of the form MIXED=TARGET."""
    if "=" not in value:
        print(
            f"ERROR: Invalid --remap format '{value}'. Expected MIXED=TARGET (e.g., 172=42).",
            file=sys.stderr,
        )
        sys.exit(1)
    parts = value.split("=", 1)
    try:
        source = int(parts[0])
        target = int(parts[1])
    except ValueError:
        print(
            f"ERROR: Invalid --remap format '{value}'. Both values must be integers.",
            file=sys.stderr,
        )
        sys.exit(1)
    return source, target


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ipanon",
        description="CIDR-aware IP anonymizer with prefix-preserving permutation.",
    )
    salt_group = parser.add_mutually_exclusive_group()
    salt_group.add_argument(
        "-s",
        "--salt",
        help="Reproducible anonymization salt (random if omitted, printed to stderr).",
    )
    salt_group.add_argument(
        "--salt-env",
        metavar="ENVNAME",
        help="Read salt from environment variable ENVNAME.",
    )
    parser.add_argument(
        "--remap",
        action="append",
        default=[],
        metavar="MIXED=TARGET",
        help=(
            "Redirect public IPs from a mixed first-octet (100, 169, 172, "
            "192, 198, 203) to a dedicated pure-public target. These octets "
            "contain both reserved sub-ranges and public IPs, so they can't "
            "join the normal permutation pool. Without --remap, public IPs "
            "from mixed octets keep their first octet unchanged (with a "
            "warning). Example: --remap 172=42. Can repeat."
        ),
    )
    parser.add_argument(
        "--pass-through",
        action="append",
        default=[],
        metavar="CIDR",
        help=(
            "Don't anonymize IPs matching CIDR prefix. Can repeat. "
            "Prefixes covering entire /8 blocks are excluded from the "
            "permutation pool (guaranteed collision-free). Narrower "
            "prefixes use post-hoc collision detection."
        ),
    )
    parser.add_argument(
        "--allow-pt-collisions",
        action="store_true",
        help=(
            "Downgrade pass-through collision errors to warnings. "
            "Only relevant for --pass-through prefixes narrower than /8."
        ),
    )
    parser.add_argument(
        "--ignore-subnets",
        action="store_true",
        help=(
            "Treat sub-/8 IPv4 Cat A ranges (172.16/12, 192.168/16, 100.64/10, "
            "169.254/16) as public. Only 10.0.0.0/8 remains range-preserved. "
            "Cat B and IPv6 are unaffected."
        ),
    )
    parser.add_argument(
        "--ignore-reserved",
        action="store_true",
        help=(
            "Remove ALL Cat A and Cat B handling. Every IP (including loopback, "
            "multicast, private ranges) gets fully anonymized as public. "
            "Affects both IPv4 and IPv6."
        ),
    )
    parser.add_argument(
        "-m",
        "--mapping",
        metavar="FILE",
        help="Write IP mapping to FILE (JSON).",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Print stats to stderr. Use -vv to also print all mappings.",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Suppress all warnings. Only errors are printed to stderr.",
    )
    parser.add_argument(
        "input_file",
        nargs="?",
        help="Input file (stdin if omitted).",
    )
    parser.add_argument(
        "output_file",
        nargs="?",
        help="Output file (stdout if omitted).",
    )
    return parser


def main(argv: Optional[List[str]] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    # Resolve salt
    salt = args.salt
    if args.salt_env:
        salt = os.environ.get(args.salt_env)
        if not salt:
            print(
                f"ERROR: Environment variable {args.salt_env} is not set or empty.",
                file=sys.stderr,
            )
            sys.exit(1)

    # Parse remaps
    remaps: Dict[int, int] = {}
    for remap_str in args.remap:
        source, target = parse_remap(remap_str)
        remaps[source] = target

    # Create anonymizer
    try:
        anonymizer = Anonymizer(
            salt=salt,
            remaps=remaps if remaps else None,
            pass_through_prefixes=args.pass_through if args.pass_through else None,
            allow_pt_collisions=args.allow_pt_collisions,
            quiet=args.quiet,
            verbose=args.verbose >= 1,
            ignore_subnets=args.ignore_subnets,
            ignore_reserved=args.ignore_reserved,
        )
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    # Read input
    if args.input_file:
        with open(args.input_file) as f:
            text = f.read()
    else:
        text = sys.stdin.read()

    # Process
    try:
        output = scan_and_replace(text, anonymizer)
    except PassThroughCollisionError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    # Write output
    if args.output_file:
        with open(args.output_file, "w") as f:
            f.write(output)
    else:
        sys.stdout.write(output)

    # Write mapping
    if args.mapping:
        mapping = anonymizer.get_mapping()
        with open(args.mapping, "w") as f:
            json.dump(mapping, f, indent=2, sort_keys=True)

    # Verbose output (suppressed by --quiet)
    if args.quiet:
        pass
    elif args.verbose >= 2:
        mapping = anonymizer.get_mapping()
        for original, anonymized in sorted(mapping.items()):
            print(f"{original} -> {anonymized}", file=sys.stderr)
        print(f"Processed {len(mapping)} unique IPs.", file=sys.stderr)
    elif args.verbose >= 1:
        mapping = anonymizer.get_mapping()
        print(f"Processed {len(mapping)} unique IPs.", file=sys.stderr)


if __name__ == "__main__":
    main()
