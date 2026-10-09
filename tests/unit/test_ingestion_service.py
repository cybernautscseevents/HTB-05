"""Unit tests for IngestionService."""

from pathlib import Path

from acsa.evidence.models import EvidenceSource
from acsa.ingestion.service import IngestionService

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_ingest_basic_repo() -> None:
    """Ingest repository containing package.json and package-lock.json."""
    service = IngestionService()
    result = service.ingest_repository(FIXTURES_DIR / "repo_basic")

    assert result.success is True
    assert len(result.discovered_artifacts) == 2
    assert len(result.inventory.observations) == 2  # 1 from manifest, 1 from lockfile
    assert len(result.inventory.components) == 1
    assert result.inventory.components[0].name == "cookie"
    assert result.inventory.components[0].version == "0.6.0"

    # Evidence checks
    assert len(result.evidence) == 2
    sources = {e.source for e in result.evidence}
    assert sources == {EvidenceSource.PACKAGE_JSON, EvidenceSource.PACKAGE_LOCK}


def test_ingest_nonexistent_repository_reports_fatal_error() -> None:
    """Nonexistent repository path returns structured IngestionResult with is_fatal=True."""
    service = IngestionService()
    result = service.ingest_repository(Path("nonexistent_path_404"))

    assert result.success is False
    assert len(result.errors) == 1
    assert result.errors[0].is_fatal is True


def test_ingest_malformed_repo_still_extracts_valid_artifacts(tmp_path: Path) -> None:
    """If one artifact is broken (e.g. malformed JSON in lockfile), valid package.json is still parsed."""
    (tmp_path / "package.json").write_text('{"name": "test", "dependencies": {"valid-pkg": "1.0.0"}}', encoding="utf-8")
    (tmp_path / "package-lock.json").write_text('{"broken json', encoding="utf-8")

    service = IngestionService()
    result = service.ingest_repository(tmp_path)

    # Partial success: package.json parsed, lockfile has error
    assert len(result.inventory.observations) == 1
    assert result.inventory.observations[0].component_name == "valid-pkg"
    assert len(result.errors) == 1
    assert "package-lock.json" in result.errors[0].artifact_path
