"""Unit tests for PackageJsonParser."""

from pathlib import Path

from acsa.evidence.models import EvidenceSource
from acsa.ingestion.models import ArtifactType, DiscoveredArtifact
from acsa.ingestion.parsers.package_json import PackageJsonParser

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_package_json_normal_parsing() -> None:
    """Parse standard package.json with production dependencies."""
    file_path = FIXTURES_DIR / "normal_pkg" / "package.json"
    artifact = DiscoveredArtifact(
        path=str(file_path),
        relative_path="package.json",
        artifact_type=ArtifactType.PACKAGE_JSON,
        size_bytes=file_path.stat().st_size,
    )

    parser = PackageJsonParser()
    observations, deps, _comps, evs, errs, warns = parser.parse(artifact)

    assert len(errs) == 0
    assert len(warns) == 0
    assert len(observations) == 2
    assert len(deps) == 2
    assert len(evs) == 1

    obs_map = {o.component_name: o for o in observations}
    assert "express" in obs_map
    assert obs_map["express"].version_constraint == "^4.18.2"
    assert obs_map["express"].version is None
    assert obs_map["express"].source_type == EvidenceSource.PACKAGE_JSON

    assert "lodash" in obs_map
    assert obs_map["lodash"].version_constraint == "^4.17.21"


def test_package_json_all_dependency_types() -> None:
    """Parse package.json with direct, dev, optional, peer, and bundled dependencies."""
    file_path = FIXTURES_DIR / "all_dep_types" / "package.json"
    artifact = DiscoveredArtifact(
        path=str(file_path),
        relative_path="package.json",
        artifact_type=ArtifactType.PACKAGE_JSON,
        size_bytes=file_path.stat().st_size,
    )

    parser = PackageJsonParser()
    observations, _deps, _comps, _evs, errs, warns = parser.parse(artifact)

    assert len(errs) == 0
    assert len(warns) == 0

    obs_by_type = {o.component_name: o.dependency_type for o in observations}
    assert obs_by_type["axios"] in ("direct", "bundled")
    assert obs_by_type["typescript"] == "dev"
    assert obs_by_type["jest"] == "dev"
    assert obs_by_type["fsevents"] == "optional"
    assert obs_by_type["react"] == "peer"


def test_package_json_malformed_json_handling() -> None:
    """Malformed package.json records IngestionError without raising unhandled exception."""
    file_path = FIXTURES_DIR / "malformed" / "malformed_json.json"
    artifact = DiscoveredArtifact(
        path=str(file_path),
        relative_path="malformed_json.json",
        artifact_type=ArtifactType.PACKAGE_JSON,
        size_bytes=file_path.stat().st_size,
    )

    parser = PackageJsonParser()
    observations, _deps, _comps, _evs, errs, _warns = parser.parse(artifact)

    assert len(errs) == 1
    assert "Malformed JSON" in errs[0].message
    assert len(observations) == 0


def test_package_json_not_an_object_handling() -> None:
    """Non-object JSON package.json records IngestionError."""
    file_path = FIXTURES_DIR / "malformed" / "not_an_object" / "package.json"
    artifact = DiscoveredArtifact(
        path=str(file_path),
        relative_path="package.json",
        artifact_type=ArtifactType.PACKAGE_JSON,
        size_bytes=file_path.stat().st_size,
    )

    parser = PackageJsonParser()
    _observations, _deps, _comps, _evs, errs, _warns = parser.parse(artifact)

    assert len(errs) == 1
    assert "JSON object" in errs[0].message
