"""Integration tests for the ACSA FastAPI health endpoints."""

from fastapi.testclient import TestClient


def test_api_health_endpoint(api_client: TestClient) -> None:
    """Verify GET /health returns expected operational status without fake vulnerability stats."""
    response = api_client.get("/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "acsa-api"
    # Verify no fake security statistics are present
    assert "vulnerabilities" not in data
    assert "findings" not in data
    assert "cve_count" not in data


def test_api_v1_health_endpoint(api_client: TestClient) -> None:
    """Verify GET /api/v1/health returns consistent status."""
    response = api_client.get("/api/v1/health")
    assert response.status_code == 200

    data = response.json()
    assert data["status"] == "ok"
    assert data["service"] == "acsa-api"
