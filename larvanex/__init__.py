"""Larvanex - beginner-friendly static malware triage."""

__version__ = "2.0.0"

from .scanner import ScanResult, build_analyzers, scan_bytes, score, verdict

__all__ = ["__version__", "ScanResult", "build_analyzers", "scan_bytes", "score", "verdict"]
