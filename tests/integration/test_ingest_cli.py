"""Integration tests for the CLI ingest command."""

import json
from pathlib import Path

from typer.testing import CliRunner

from acsa.cli.main import app

runner = CliRunner()
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_cli_ingest_basic_repo() -> None:
    """CLI ingest command runs successfully on a valid repository workspace."""
    repo_path = str(FIXTURES_DIR / "repo_basic")
    result = runner.invoke(app, ["ingest", repo_path])

    assert result.exit_code == 0
    assert "ACSA Artifact Ingestion Report" in result.stdout
    assert "Discovered Artifacts" in result.stdout
    assert "package.json" in result.stdout
    assert "package-lock.json" in result.stdout
    assert "Ingestion Summary" in result.stdout


def test_cli_ingest_contradictory_repo_highlights_discrepancy() -> None:
    """CLI ingest highlights multi-source version discrepancies when present."""
    repo_path = str(FIXTURES_DIR / "repo_contradictory")
    result = runner.invoke(app, ["ingest", repo_path])

    assert result.exit_code == 0
    assert "Multi-Source Observations with Version Discrepancies" in result.stdout
    assert "lodash" in result.stdout


def test_cli_ingest_json_output() -> None:
    """CLI ingest --json produces parseable machine-readable JSON."""
    repo_path = str(FIXTURES_DIR / "repo_basic")
    result = runner.invoke(app, ["ingest", repo_path, "--json"])

    assert result.exit_code == 0
    data = json.loads(result.stdout)
    assert data["success"] is True
    assert "discovered_artifacts" in data
    assert "inventory" in data
    assert len(data["discovered_artifacts"]) == 2
