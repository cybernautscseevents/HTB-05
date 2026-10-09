"""Unit tests for CycloneDxParser."""

from pathlib import Path

from acsa.evidence.models import EvidenceSource
from acsa.ingestion.models import ArtifactType, DiscoveredArtifact
from acsa.ingestion.parsers.cyclonedx import CycloneDxParser

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_cyclonedx_sbom_parsing() -> None:
    """Parse CycloneDX 1.5 JSON SBOM fixture."""
    file_path = FIXTURES_DIR / "cyclonedx_sbom" / "bom.json"
    artifact = DiscoveredArtifact(
        path=str(file_path),
        relative_path="bom.json",
        artifact_type=ArtifactType.CYCLONEDX_JSON,
        size_bytes=file_path.stat().st_size,
    )

    parser = CycloneDxParser()
    observations, _deps, _comps, _evs, errs, warns = parser.parse(artifact)

    assert len(errs) == 0
    assert len(warns) == 0
    assert len(observations) == 2

    obs_map = {o.component_name: o for o in observations}
    assert "lodash" in obs_map
    assert obs_map["lodash"].version == "4.17.21"
    assert obs_map["lodash"].source_type == EvidenceSource.CYCLONEDX_SBOM
    assert obs_map["lodash"].purl == "pkg:npm/lodash@4.17.21"
    assert "MIT" in obs_map["lodash"].licenses
    assert obs_map["lodash"].integrity is not None
    assert obs_map["lodash"].integrity.startswith("SHA-256:")

    assert "express" in obs_map
    assert obs_map["express"].version == "4.18.2"


def test_cyclonedx_malformed_handling(tmp_path: Path) -> None:
    """Malformed CycloneDX JSON document is handled gracefully."""
    broken_file = tmp_path / "bom.json"
    broken_file.write_text('{"bomFormat": "CycloneDX", "components": "not-a-list"}', encoding="utf-8")

    artifact = DiscoveredArtifact(
        path=str(broken_file),
        relative_path="bom.json",
        artifact_type=ArtifactType.CYCLONEDX_JSON,
        size_bytes=broken_file.stat().st_size,
    )

    parser = CycloneDxParser()
    observations, _deps, _comps, _evs, _errs, warns = parser.parse(artifact)
    assert len(warns) == 1
    assert "not an array" in warns[0].message
    assert len(observations) == 0
