"""CIDR-aware IP anonymizer with prefix-preserving permutation."""

__version__ = "0.2.1"

from ipanon.anonymizer import Anonymizer, PassThroughCollisionError
from ipanon.ranges import Category, classify_ip
from ipanon.scanner import find_ips, scan_and_replace

__all__ = [
    "Anonymizer",
    "Category",
    "PassThroughCollisionError",
    "classify_ip",
    "find_ips",
    "scan_and_replace",
]
