"""SBOM ingestion, normalization (CycloneDX, SPDX), and discrepancy detection for ACSA."""

from acsa.ingestion.parsers.cyclonedx import CycloneDxParser
from acsa.ingestion.parsers.spdx import SpdxParser

__all__ = ["CycloneDxParser", "SpdxParser"]
