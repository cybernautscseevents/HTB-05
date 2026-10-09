"""Unit tests for PackageLockParser supporting v1, v2, and v3."""

from pathlib import Path

from acsa.evidence.models import EvidenceSource
from acsa.ingestion.models import ArtifactType, DiscoveredArtifact
from acsa.ingestion.parsers.package_lock import PackageLockParser

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_package_lock_v3_parsing() -> None:
    """Parse lockfile v3 with packages dictionary structure."""
    file_path = FIXTURES_DIR / "lockfile_v3" / "package-lock.json"
    artifact = DiscoveredArtifact(
        path=str(file_path),
        relative_path="package-lock.json",
        artifact_type=ArtifactType.PACKAGE_LOCK,
        size_bytes=file_path.stat().st_size,
    )

    parser = PackageLockParser()
    observations, _deps, _comps, _evs, errs, warns = parser.parse(artifact)

    assert len(errs) == 0
    assert len(warns) == 0
    assert len(observations) == 3  # express, lodash, @types/node

    obs_map = {o.component_name: o for o in observations}
    assert "lodash" in obs_map
    assert obs_map["lodash"].version == "4.17.21"
    assert obs_map["lodash"].source_type == EvidenceSource.PACKAGE_LOCK
    assert obs_map["lodash"].resolved_url == "https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz"
    assert obs_map["lodash"].dependency_type == "direct"

    assert "express" in obs_map
    assert obs_map["express"].version == "4.18.2"

    assert "@types/node" in obs_map
    assert obs_map["@types/node"].version == "20.11.0"
    assert obs_map["@types/node"].dependency_type == "dev"


def test_package_lock_v1_parsing() -> None:
    """Parse lockfile v1 with recursive dependencies structure."""
    file_path = FIXTURES_DIR / "lockfile_v1" / "package-lock.json"
    artifact = DiscoveredArtifact(
        path=str(file_path),
        relative_path="package-lock.json",
        artifact_type=ArtifactType.PACKAGE_LOCK,
        size_bytes=file_path.stat().st_size,
    )

    parser = PackageLockParser()
    observations, _deps, _comps, _evs, errs, warns = parser.parse(artifact)

    assert len(errs) == 0
    assert len(warns) == 0

    obs_map = {o.component_name: o for o in observations}
    assert "debug" in obs_map
    assert obs_map["debug"].version == "4.3.4"
    assert "ms" in obs_map
    assert obs_map["ms"].version == "2.1.2"


def test_package_lock_unsupported_version_warning() -> None:
    """Unrecognized lockfile version logs IngestionWarning without fatal crash."""
    file_path = FIXTURES_DIR / "malformed" / "invalid_lockfile_version" / "package-lock.json"
    artifact = DiscoveredArtifact(
        path=str(file_path),
        relative_path="package-lock.json",
        artifact_type=ArtifactType.PACKAGE_LOCK,
        size_bytes=file_path.stat().st_size,
    )

    parser = PackageLockParser()
    _observations, _deps, _comps, _evs, errs, warns = parser.parse(artifact)

    assert len(errs) == 0
    assert len(warns) == 1
    assert "unsupported lockfileVersion" in warns[0].message
