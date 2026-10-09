"""Integration tests for POST /api/v1/remediation/verify API endpoint."""

from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from fastapi.testclient import TestClient

from acsa.api.app import app

client = TestClient(app)
FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "phase4"


@patch("acsa.vulnerability.service.OSVClient")
def test_api_verify_remediation_mode_a(mock_client_cls: MagicMock) -> None:
    """Verify POST /api/v1/remediation/verify in Mode A (simulated lockfile regeneration).

    Lockfile not regenerated -> REQUIRES_VERIFICATION.
    """
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
    response = client.post(
        "/api/v1/remediation/verify",
        json={"repository_path": str(target), "mode": "MODE_A_SIMULATED"},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["verification_mode"] == "MODE_A_SIMULATED"
    assert data["total_candidates_verified"] >= 1
    assert len(data["results"]) >= 1

    item = data["results"][0]
    assert item["target_component"] == "lodash"
    assert item["verification_status"] == "REQUIRES_VERIFICATION"
    assert "package-lock.json" in str(item["missing_evidence"]).lower()
    assert item["before"] is not None
    assert item["after"] is not None
    assert item["proof_conditions"] is not None


@patch("acsa.vulnerability.service.OSVClient")
def test_api_verify_remediation_mode_b(mock_client_cls: MagicMock) -> None:
    """Verify POST /api/v1/remediation/verify in Mode B (materialized post-remediation dependency).

    Version becomes safe -> PROVEN_REMEDIATED.
    """
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    def mock_query_batch(queries: Any) -> dict[Any, Any]:
        res = {}
        for eco, name, ver in queries:
            if name == "lodash" and ver == "4.17.19":
                res[(eco, name, ver)] = ["GHSA-29mw-wpgm-hmr9"]
            else:
                res[(eco, name, ver)] = []
        return res

    mock_client.query_batch.side_effect = mock_query_batch
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
    response = client.post(
        "/api/v1/remediation/verify",
        json={"repository_path": str(target), "mode": "MODE_B_MATERIALIZED"},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["verification_mode"] == "MODE_B_MATERIALIZED"
    assert data["total_candidates_verified"] >= 1

    item = data["results"][0]
    assert item["target_component"] == "lodash"
    assert item["proof_conditions"]["version_closed"] is True
    assert item["verification_status"] == "PROVEN_REMEDIATED"


@patch("acsa.vulnerability.service.OSVClient")
def test_api_verify_remediation_contradictory_inventory_empty_results(mock_client_cls: MagicMock) -> None:
    """Verify that contradictory inventory produces total_candidates_verified=0 and empty results with warning."""
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.query_batch.return_value = {
        ("npm", "lodash", "4.17.19"): ["GHSA-29mw-wpgm-hmr9"],
        ("npm", "lodash", "4.17.21"): ["GHSA-29mw-wpgm-hmr9"],
    }
    mock_client.get_vulnerability.return_value = {
        "id": "GHSA-29mw-wpgm-hmr9",
        "summary": "Prototype Pollution in lodash",
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
            }
        ],
    }

    contradictory_repo = FIXTURES_DIR.parent / "repo_contradictory"
    response = client.post(
        "/api/v1/remediation/verify",
        json={"repository_path": str(contradictory_repo), "mode": "MODE_A_SIMULATED"},
    )

    assert response.status_code == 200
    data = response.json()

    assert data["total_candidates_verified"] == 0
    assert data["results"] == []
    assert data["warning"] is not None
    assert "contradictory" in data["warning"].lower() or "block" in data["warning"].lower()


@patch("acsa.vulnerability.service.OSVClient")
def test_api_verify_remediation_nonexistent_candidate(mock_client_cls: MagicMock) -> None:
    """Verify requesting an unknown candidate returns total_candidates_verified=0 and informative summary."""
    mock_client = MagicMock()
    mock_client_cls.return_value = mock_client
    mock_client.query_batch.return_value = {}

    target = FIXTURES_DIR / "confirmed_exposure"
    response = client.post(
        "/api/v1/remediation/verify",
        json={
            "repository_path": str(target),
            "candidate_id": "nonexistent-candidate-xyz",
            "mode": "MODE_A_SIMULATED",
        },
    )

    assert response.status_code == 200
    data = response.json()

    assert data["total_candidates_verified"] == 0
    assert data["results"] == []
    assert "nonexistent-candidate-xyz" in (data["warning"] or data["summary"])


def test_api_verify_remediation_path_security_violation() -> None:
    """Verify path security violation returns HTTP 400 Bad Request."""
    response = client.post(
        "/api/v1/remediation/verify",
        json={"repository_path": "invalid\x00path", "mode": "MODE_A_SIMULATED"},
    )
    assert response.status_code == 400
    assert "Path security violation" in response.json()["detail"]


def test_api_verify_remediation_not_found_directory() -> None:
    """Verify non-existent repository path returns HTTP 404 Not Found."""
    response = client.post(
        "/api/v1/remediation/verify",
        json={
            "repository_path": "tests/fixtures/does_not_exist_workspace_12345",
            "mode": "MODE_A_SIMULATED",
        },
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()
