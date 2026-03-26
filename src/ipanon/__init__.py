"""CIDR-aware IP anonymizer with prefix-preserving permutation."""

__version__ = "0.3.2"

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
