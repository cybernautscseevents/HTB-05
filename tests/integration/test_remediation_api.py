"""Integration tests for POST /api/v1/remediate API endpoint."""

from pathlib import Path
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from acsa.api.app import app

client = TestClient(app)
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "phase4"


@patch("acsa.vulnerability.service.OSVClient")
def test_api_remediate_success(mock_client_cls: MagicMock) -> None:
    """Verify POST /api/v1/remediate returns ranked remediation candidates, simulated patches, and verification specs."""
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
    response = client.post("/api/v1/remediate", json={"repository_path": str(target)})

    assert response.status_code == 200
    data = response.json()

    assert data["total_findings_evaluated"] == 1
    assert data["remediated_findings_count"] == 1
    assert len(data["results"]) == 1

    res = data["results"][0]
    assert res["package_name"] == "lodash"
    assert res["current_version"] == "4.17.19"
    assert res["dependency_relation"] == "DIRECT"

    # Selected candidate
    selected = res["selected_candidate"]
    assert selected is not None
    assert selected["strategy"] == "DIRECT_UPGRADE"
    assert selected["target_version"] == "4.17.21"
    assert selected["version_impact"] == "PATCH"
    assert selected["closure_status"] == "PROVEN_CLOSED"
    assert selected["confidence_level"] == "HIGH"
    assert selected["lockfile_action"] == "LOCKFILE_REGENERATION_REQUIRED"
    assert selected["simulated_patch"] is not None
    assert "package.json" in selected["simulated_patch"]
    assert "+    \"lodash\": \"^4.17.21\"" in selected["simulated_patch"] or "4.17.21" in selected["simulated_patch"]

    # Verification specification
    v_spec = res["verification_spec"]
    assert v_spec is not None
    assert v_spec["expected_after_version"] == "4.17.21"
    assert "GHSA-29mw-wpgm-hmr9" in v_spec["expected_closed_advisories"]


def test_api_remediate_path_traversal_blocked() -> None:
    """Path traversal attempt in POST /api/v1/remediate must return 400 Bad Request."""
    response = client.post(
        "/api/v1/remediate",
        json={"repository_path": "package.json\x00.exe"},
    )
    assert response.status_code == 400


def test_api_remediate_nonexistent_directory() -> None:
    """Nonexistent repository directory in POST /api/v1/remediate returns 404 Not Found."""
    response = client.post(
        "/api/v1/remediate",
        json={"repository_path": "C:\\nonexistent\\repo\\path"},
    )
    assert response.status_code == 404
