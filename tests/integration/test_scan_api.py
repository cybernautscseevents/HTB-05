"""Integration tests for the /scan and /api/v1/scan REST API endpoints."""

from unittest.mock import patch

from fastapi.testclient import TestClient

from acsa.api.app import app
from acsa.inventory.models import CanonicalInventory, Component
from acsa.vulnerability.models import VulnerabilityScanResult

client = TestClient(app)


def test_api_scan_endpoint_success() -> None:
    """POST /api/v1/scan returns HTTP 200 and structured VulnerabilityScanResult schema."""
    sample_result = VulnerabilityScanResult(
        repository_path="tests/fixtures/repo_basic",
        inventory=CanonicalInventory(
            observations=[],
            components=[Component(name="cookie", version="0.6.0")],
            dependencies=[],
        ),
        findings=[],
        vulnerabilities=[],
        evidence=[],
        queries_executed=1,
        exact_versions_queried=1,
        advisories_count=0,
        affected_count=0,
        not_affected_count=0,
        unknown_count=0,
        osv_available=True,
        errors=[],
    )

    with patch(
        "acsa.vulnerability.service.VulnerabilityService.scan_inventory",
        return_value=sample_result,
    ):
        response = client.post(
            "/api/v1/scan",
            json={"repository_path": "tests/fixtures/repo_basic"},
        )
        assert response.status_code == 200
        data = response.json()
        assert "inventory" in data
        assert data["exact_versions_queried"] == 1
        assert data["osv_available"] is True


def test_api_scan_root_endpoint_success() -> None:
    """POST /scan at root also returns HTTP 200."""
    sample_result = VulnerabilityScanResult(
        repository_path="tests/fixtures/repo_basic",
        inventory=CanonicalInventory(observations=[], components=[], dependencies=[]),
        findings=[],
        vulnerabilities=[],
        evidence=[],
        queries_executed=0,
        exact_versions_queried=0,
        advisories_count=0,
        affected_count=0,
        not_affected_count=0,
        unknown_count=0,
        osv_available=True,
        errors=[],
    )

    with patch(
        "acsa.vulnerability.service.VulnerabilityService.scan_inventory",
        return_value=sample_result,
    ):
        response = client.post(
            "/scan",
            json={"repository_path": "tests/fixtures/repo_basic"},
        )
        assert response.status_code == 200


def test_api_scan_path_traversal_blocked() -> None:
    """Dangerous path traversal attempts are blocked with HTTP 400."""
    response = client.post(
        "/api/v1/scan",
        json={"repository_path": "valid_path\x00_inject"},
    )
    assert response.status_code == 400
    assert "security violation" in response.json()["detail"].lower()


def test_api_scan_not_found() -> None:
    """Non-existent repository workspace paths return HTTP 404."""
    response = client.post(
        "/api/v1/scan",
        json={"repository_path": "tests/fixtures/does_not_exist_xyz"},
    )
    assert response.status_code == 404


def test_scan_semver_ghsa_c2qf_rxjj_qqgw_end_to_end_regression() -> None:
    """Regression test: complete scan-to-finding response for GHSA-c2qf-rxjj-qqgw in nodegoat.

    Proves that:
    1. Vulnerable symbols does NOT contain 'the' (must be empty list).
    2. Reachability is UNKNOWN (not NOT_REACHABLE based on a generic word).
    3. Reachability target_symbol is None (not 'the').
    4. Exact version applicability remains AFFECTED.
    5. Verdict is UNKNOWN (UNKNOWN != SAFE).
    """
    response = client.post(
        "/api/v1/scan",
        json={"repository_path": "tests/fixtures/nodegoat"},
    )
    assert response.status_code == 200
    data = response.json()

    findings = data.get("findings", [])
    semver_c2qf_findings = [
        f
        for f in findings
        if f.get("component", {}).get("name") == "semver"
        and f.get("vulnerability", {}).get("id") == "GHSA-c2qf-rxjj-qqgw"
    ]

    assert len(semver_c2qf_findings) > 0, "Expected at least one semver GHSA-c2qf-rxjj-qqgw finding in nodegoat"

    # Specifically check semver@5.7.0
    finding_570 = next(
        (f for f in semver_c2qf_findings if f.get("component", {}).get("version") == "5.7.0"),
        None,
    )
    assert finding_570 is not None, "semver@5.7.0 finding not found"

    for f in semver_c2qf_findings:
        vuln = f.get("vulnerability", {})
        reach = f.get("reachability", {})
        verdict = f.get("verdict")
        app_status = f.get("applicability_status")

        # 1. Symbol validation: 'the' must NEVER be treated as a vulnerable symbol
        assert "the" not in vuln.get("vulnerable_symbols", [])
        assert vuln.get("vulnerable_symbols") == []

        # 2. Reachability validation: must be UNKNOWN, not NOT_REACHABLE
        assert reach.get("status") == "UNKNOWN"
        assert reach.get("target_symbol") is None
        assert reach.get("target_symbol") != "the"

        # 3. Applicability & Exposure separation: installed version is AFFECTED, but verdict is UNKNOWN
        assert app_status == "AFFECTED"
        assert verdict == "UNKNOWN"
        assert "no usable vulnerable symbol" in (reach.get("uncertainty_reason") or "").lower()

