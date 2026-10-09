"""Unit tests for SpdxParser."""

from pathlib import Path

from acsa.evidence.models import EvidenceSource
from acsa.ingestion.models import ArtifactType, DiscoveredArtifact
from acsa.ingestion.parsers.spdx import SpdxParser

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_spdx_sbom_parsing() -> None:
    """Parse SPDX 2.3 JSON SBOM fixture."""
    file_path = FIXTURES_DIR / "spdx_sbom" / "spdx.json"
    artifact = DiscoveredArtifact(
        path=str(file_path),
        relative_path="spdx.json",
        artifact_type=ArtifactType.SPDX_JSON,
        size_bytes=file_path.stat().st_size,
    )

    parser = SpdxParser()
    observations, _deps, _comps, _evs, errs, warns = parser.parse(artifact)

    assert len(errs) == 0
    assert len(warns) == 0
    assert len(observations) == 1

    obs = observations[0]
    assert obs.component_name == "semver"
    assert obs.version == "7.5.4"
    assert obs.source_type == EvidenceSource.SPDX_SBOM
    assert obs.purl == "pkg:npm/semver@7.5.4"
    assert "ISC" in obs.licenses
    assert obs.integrity is not None
    assert obs.integrity.startswith("SHA256:")
    assert obs.raw_metadata["SPDXID"] == "SPDXRef-Package-semver"


def test_spdx_malformed_handling(tmp_path: Path) -> None:
    """Non-array packages field in SPDX document triggers IngestionWarning."""
    broken_file = tmp_path / "spdx.json"
    broken_file.write_text('{"spdxVersion": "SPDX-2.3", "packages": "invalid"}', encoding="utf-8")

    artifact = DiscoveredArtifact(
        path=str(broken_file),
        relative_path="spdx.json",
        artifact_type=ArtifactType.SPDX_JSON,
        size_bytes=broken_file.stat().st_size,
    )

    parser = SpdxParser()
    observations, _deps, _comps, _evs, _errs, warns = parser.parse(artifact)
    assert len(warns) == 1
    assert "not an array" in warns[0].message
    assert len(observations) == 0
