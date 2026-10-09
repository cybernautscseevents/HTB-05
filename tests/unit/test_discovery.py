"""Unit tests for ArtifactDiscovery."""

from pathlib import Path

from acsa.ingestion.discovery import ArtifactDiscovery
from acsa.ingestion.models import ArtifactType

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_discovery_in_normal_pkg() -> None:
    """ArtifactDiscovery finds package.json in normal package fixture."""
    discovery = ArtifactDiscovery()
    artifacts, warnings = discovery.discover(FIXTURES_DIR / "normal_pkg")
    assert len(warnings) == 0
    assert len(artifacts) == 1
    assert artifacts[0].artifact_type == ArtifactType.PACKAGE_JSON
    assert artifacts[0].relative_path == "package.json"
    assert artifacts[0].size_bytes > 0
    assert artifacts[0].sha256 is not None


def test_discovery_in_cyclonedx_sbom() -> None:
    """ArtifactDiscovery identifies CycloneDX JSON SBOM."""
    discovery = ArtifactDiscovery()
    artifacts, warnings = discovery.discover(FIXTURES_DIR / "cyclonedx_sbom")
    assert len(warnings) == 0
    assert len(artifacts) == 1
    assert artifacts[0].artifact_type == ArtifactType.CYCLONEDX_JSON
    assert artifacts[0].relative_path == "bom.json"


def test_discovery_in_spdx_sbom() -> None:
    """ArtifactDiscovery identifies SPDX JSON SBOM."""
    discovery = ArtifactDiscovery()
    artifacts, warnings = discovery.discover(FIXTURES_DIR / "spdx_sbom")
    assert len(warnings) == 0
    assert len(artifacts) == 1
    assert artifacts[0].artifact_type == ArtifactType.SPDX_JSON
    assert artifacts[0].relative_path == "spdx.json"


def test_discovery_in_multi_artifact_repo() -> None:
    """ArtifactDiscovery discovers manifest, lockfile, and SBOM together."""
    discovery = ArtifactDiscovery()
    artifacts, warnings = discovery.discover(FIXTURES_DIR / "repo_contradictory")
    assert len(warnings) == 0
    types = {a.artifact_type for a in artifacts}
    assert types == {
        ArtifactType.PACKAGE_JSON,
        ArtifactType.PACKAGE_LOCK,
        ArtifactType.CYCLONEDX_JSON,
    }


def test_discovery_skips_ignored_directories(tmp_path: Path) -> None:
    """ArtifactDiscovery ignores node_modules and .git directories."""
    # Create valid root package.json
    (tmp_path / "package.json").write_text('{"name": "root"}', encoding="utf-8")

    # Create node_modules and nested package.json
    nm_dir = tmp_path / "node_modules" / "some-lib"
    nm_dir.mkdir(parents=True, exist_ok=True)
    (nm_dir / "package.json").write_text('{"name": "some-lib"}', encoding="utf-8")

    discovery = ArtifactDiscovery()
    artifacts, _warnings = discovery.discover(tmp_path)
    assert len(artifacts) == 1
    assert artifacts[0].relative_path == "package.json"


def test_discovery_respects_max_file_size(tmp_path: Path) -> None:
    """ArtifactDiscovery ignores files that exceed max size quota."""
    large_file = tmp_path / "package.json"
    large_file.write_text('{"name": "large"}', encoding="utf-8")

    # Set quota smaller than file size
    discovery = ArtifactDiscovery(max_file_size_bytes=5)
    artifacts, warnings = discovery.discover(tmp_path)
    assert len(artifacts) == 0
    assert len(warnings) == 1
    assert "exceeding size limit" in warnings[0].message
