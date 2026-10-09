"""Integration tests for POST /api/v1/scan Phase 4 context and verdict responses."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from acsa.api.app import app
from acsa.verdict.vocabulary import Verdict

client = TestClient(app)
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "phase4"


@patch("acsa.vulnerability.service.OSVClient")
def test_api_scan_returns_context_and_verdict(mock_client_cls: MagicMock) -> None:
    """Verify POST /api/v1/scan returns structured finding, applicability, reachability, context, evidence, and verdict."""
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

    target = FIXTURES_DIR / "confirmed_exposure"
    response = client.post("/api/v1/scan", json={"repository_path": str(target)})

    assert response.status_code == 200
    data = response.json()

    assert data["context_evaluated"] is True
    assert data["fusion_evaluated"] is True
    assert data["proven_exposure_count"] == 1

    findings = data["findings"]
    assert len(findings) == 1
    f = findings[0]
    assert f["verdict"] == Verdict.PROVEN_EXPOSURE.value
    assert f["applicability_status"] == "AFFECTED"

    # Check Reachability block
    reach = f["reachability"]
    assert reach is not None
    assert reach["status"] == "REACHABLE"
    assert reach["target_symbol"] == "template"

    # Check Context block
    ctx = f["context"]
    assert ctx is not None
    assert ctx["status"] == "CONFIRMED"
    assert ctx["source"]["expression"] == "req.body.template"
    assert ctx["entry_point"] == "POST /render"
    assert "lodash.template" in ctx["sink"]
    assert len(ctx["data_flow_path"]) >= 3

    # Check evidence list
    assert len(data["evidence"]) >= 1
