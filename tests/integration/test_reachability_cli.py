"""Integration tests for CLI acsa scan reachability output."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

from typer.testing import CliRunner

from acsa.cli.main import app

runner = CliRunner()
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "reachability"


@patch("acsa.vulnerability.service.OSVClient")
def test_cli_scan_displays_reachability_section_and_evidence_path(mock_client_cls: MagicMock) -> None:
    """CLI acsa scan outputs reachability table, status, entry point, and arrow evidence paths."""
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client

    # Mock OSV returning an advisory with vulnerable_symbols=["template"] for lodash 4.17.19
    mock_client.query_batch.return_value = {
        ("npm", "lodash", "4.17.19"): ["GHSA-29mw-wpgm-hmr9"]
    }
    mock_client.get_vulnerability.return_value = {
        "id": "GHSA-29mw-wpgm-hmr9",
        "summary": "Prototype Pollution in lodash",
        "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/HIGH"}],
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
                "ecosystem_specific": {"affected_functions": ["template"]},
            }
        ],
    }

    repo_path = FIXTURES_DIR / "direct_reachable"
    result = runner.invoke(app, ["scan", str(repo_path)])

    assert result.exit_code == 0
    # Check Reachability table and details
    assert "Reachability Analysis Summary" in result.output
    assert "REACHABLE" in result.output
    assert "Entry point:" in result.output
    assert "src/server.js:6" in result.output
    assert "Vulnerable symbol:" in result.output
    assert "template" in result.output
    assert "Evidence path:" in result.output


@patch("acsa.vulnerability.service.OSVClient")
def test_cli_scan_json_includes_reachability_schema(mock_client_cls: MagicMock) -> None:
    """CLI acsa scan --json outputs reachability results and reachability_evaluated flag."""
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client

    mock_client.query_batch.return_value = {
        ("npm", "lodash", "4.17.19"): ["GHSA-29mw-wpgm-hmr9"]
    }
    mock_client.get_vulnerability.return_value = {
        "id": "GHSA-29mw-wpgm-hmr9",
        "summary": "Prototype Pollution in lodash",
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
                "ecosystem_specific": {"affected_functions": ["template"]},
            }
        ],
    }

    repo_path = FIXTURES_DIR / "direct_reachable"
    result = runner.invoke(app, ["scan", str(repo_path), "--json"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["reachability_evaluated"] is True
    assert len(payload["findings"]) >= 1
    finding = payload["findings"][0]
    assert finding["reachability"] is not None
    assert finding["reachability"]["status"] == "REACHABLE"
    assert finding["reachability"]["target_symbol"] == "template"
