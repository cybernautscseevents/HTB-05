"""Integration tests for API POST /api/v1/scan reachability enrichment."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from acsa.api.app import app

client = TestClient(app)
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "reachability"


@patch("acsa.vulnerability.service.OSVClient")
def test_api_scan_returns_reachability_data(mock_client_cls: MagicMock) -> None:
    """POST /api/v1/scan returns findings with evaluated reachability schemas and status."""
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
    response = client.post("/api/v1/scan", json={"repository_path": str(repo_path)})

    assert response.status_code == 200
    data = response.json()
    assert data["reachability_evaluated"] is True
    assert len(data["findings"]) >= 1

    finding = data["findings"][0]
    reachability = finding.get("reachability")
    assert reachability is not None
    assert reachability["status"] == "REACHABLE"
    assert reachability["target_symbol"] == "template"
    assert "src/server.js:6" in reachability["entry_point"]
    assert "src/server.js:7" in reachability["call_site"]
    assert len(reachability["evidence_path"]) >= 2
