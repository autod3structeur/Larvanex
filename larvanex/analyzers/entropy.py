"""Measure randomness. Packed or encrypted payloads look almost random,
so very high entropy is a warning sign (except for already-compressed media)."""

from __future__ import annotations

from .base import Analyzer, Finding, FileContext
from ..utils import format_size, shannon_entropy, sliding_entropy

COMPRESSED_TYPES = {
    "ZIP archive", "OLE / legacy Office document", "RAR archive", "7-Zip archive",
    "GZIP archive", "BZIP2 archive", "XZ archive", "PNG image", "JPEG image",
    "GIF image", "MP3 audio", "Ogg media", "RIFF container (WAV/AVI/WEBP)",
}


class EntropyAnalyzer(Analyzer):
    name = "entropy"

    def analyze(self, ctx: FileContext) -> list[Finding]:
        findings: list[Finding] = []
        if ctx.size < 256:
            findings.append(
                Finding(
                    category=self.name,
                    severity="info",
                    message="File too small for entropy analysis",
                    detail=f"Size: {format_size(ctx.size)}",
                )
            )
            return findings

        overall = shannon_entropy(ctx.data)
        findings.append(
            Finding(
                category=self.name,
                severity="info",
                message=f"Overall entropy: {overall:.2f} / 8.00",
                detail=f"Analysed {format_size(ctx.size)}.",
            )
        )

        if overall >= 7.9:
            findings.append(
                Finding(
                    category=self.name,
                    severity="medium",
                    message=f"Very high entropy ({overall:.2f}) across the whole file",
                    detail="Consistent with an encrypted or packed payload, or a compressed archive.",
                )
            )

        blocks = sliding_entropy(ctx.data)
        hot = [(offset, value) for offset, value in blocks if value >= 7.95]
        if len(hot) >= 2:
            sample = ", ".join(f"0x{o:x}" for o, _ in hot[:5])
            findings.append(
                Finding(
                    category=self.name,
                    severity="medium",
                    message=f"{len(hot)} high-entropy regions found",
                    detail=f"Likely embedded compressed/encrypted blobs at: {sample}",
                )
            )
        return findings
