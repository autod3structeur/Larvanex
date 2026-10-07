"""Larvanex - beginner-friendly static malware triage."""

__version__ = "1.0.0"

from .scanner import build_analyzers, scan_bytes, score, verdict

__all__ = ["__version__", "build_analyzers", "scan_bytes", "score", "verdict"]
