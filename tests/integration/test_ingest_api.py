"""Integration tests for the API ingest endpoint."""

from pathlib import Path

from fastapi.testclient import TestClient

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_api_ingest_endpoint_success(api_client: TestClient) -> None:
    """POST /api/v1/ingest successfully ingests a valid repository workspace."""
    repo_path = str((FIXTURES_DIR / "repo_basic").resolve())
    response = api_client.post("/api/v1/ingest", json={"repository_path": repo_path})

    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert len(data["discovered_artifacts"]) == 2
    assert "inventory" in data
    assert len(data["inventory"]["observations"]) == 2


def test_api_ingest_root_endpoint_success(api_client: TestClient) -> None:
    """POST /ingest also responds with consistent payload."""
    repo_path = str((FIXTURES_DIR / "repo_basic").resolve())
    response = api_client.post("/ingest", json={"repository_path": repo_path})

    assert response.status_code == 200
    assert response.json()["success"] is True


def test_api_ingest_not_found(api_client: TestClient) -> None:
    """POST /api/v1/ingest returns 404 for non-existent workspace path."""
    response = api_client.post(
        "/api/v1/ingest",
        json={"repository_path": str(Path("does_not_exist_xyz_404").resolve())},
    )
    assert response.status_code == 404
    assert "not found" in response.json()["detail"].lower()


def test_api_ingest_path_traversal_blocked(api_client: TestClient) -> None:
    """POST /api/v1/ingest blocks dangerous traversal payloads like null bytes."""
    response = api_client.post(
        "/api/v1/ingest",
        json={"repository_path": "valid_path\x00_inject"},
    )
    assert response.status_code == 400
    assert "security violation" in response.json()["detail"].lower()
