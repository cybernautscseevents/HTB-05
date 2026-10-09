"""Verdict, classification, and multi-source evidence fusion module for ACSA."""

from acsa.verdict.fusion import EvidenceFusionEngine
from acsa.verdict.service import EvidenceFusionService
from acsa.verdict.vocabulary import Verdict

__all__ = [
    "EvidenceFusionEngine",
    "EvidenceFusionService",
    "Verdict",
]
