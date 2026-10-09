"""Integration tests for ACSA CLI scan command."""

from unittest.mock import patch

from typer.testing import CliRunner

from acsa.cli.main import app
from acsa.evidence.models import EvidenceSource
from acsa.inventory.models import CanonicalInventory, Component, InventoryObservation
from acsa.verdict.vocabulary import Verdict
from acsa.vulnerability.models import (
    ApplicabilityStatus,
    Finding,
    Vulnerability,
    VulnerabilityScanResult,
)

runner = CliRunner()


def test_cli_scan_command_terminal_report() -> None:
    """Verify acsa scan runs ingestion and displays summary tables."""
    sample_result = VulnerabilityScanResult(
        repository_path="tests/fixtures/repo_basic",
        inventory=CanonicalInventory(
            observations=[
                InventoryObservation(
                    component_name="cookie",
                    version="0.6.0",
                    source_type=EvidenceSource.PACKAGE_LOCK,
                    source_artifact_path="package-lock.json",
                )
            ],
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
        result = runner.invoke(app, ["scan", "tests/fixtures/repo_basic"])
        assert result.exit_code == 0
        assert "ACSA Security Analysis" in result.output
        assert "Inventory Truth Summary" in result.output
        assert "Vulnerability Intelligence Summary" in result.output
        assert "No vulnerabilities reported" in result.output


def test_cli_scan_command_json_output() -> None:
    """Verify acsa scan --json produces valid parseable JSON."""
    mock_vuln = Vulnerability(
        id="GHSA-test-vuln",
        summary="Test advisory",
        affected_ranges=["< 1.0.0"],
        fixed_versions=["1.0.0"],
    )
    mock_comp = Component(name="test-pkg", version="0.9.0")
    mock_finding = Finding(
        vulnerability=mock_vuln,
        component=mock_comp,
        verdict=Verdict.POTENTIALLY_AFFECTED,
        applicability_status=ApplicabilityStatus.AFFECTED,
    )

    sample_result = VulnerabilityScanResult(
        repository_path="tests/fixtures/repo_basic",
        inventory=CanonicalInventory(observations=[], components=[], dependencies=[]),
        findings=[mock_finding],
        vulnerabilities=[mock_vuln],
        evidence=[],
        queries_executed=1,
        exact_versions_queried=1,
        advisories_count=1,
        affected_count=1,
        not_affected_count=0,
        unknown_count=0,
        osv_available=True,
        errors=[],
    )

    with patch(
        "acsa.vulnerability.service.VulnerabilityService.scan_inventory",
        return_value=sample_result,
    ):
        result = runner.invoke(app, ["scan", "tests/fixtures/repo_basic", "--json"])
        assert result.exit_code == 0
        import json
        data = json.loads(result.output)
        assert data["exact_versions_queried"] == 1
        assert len(data["findings"]) == 1
        assert data["findings"][0]["vulnerability"]["id"] == "GHSA-test-vuln"


def test_cli_scan_osv_unavailable_output() -> None:
    """Verify CLI reports OSV unavailability clearly instead of claiming 0 vulns."""
    sample_result = VulnerabilityScanResult(
        repository_path="tests/fixtures/repo_basic",
        inventory=CanonicalInventory(observations=[], components=[], dependencies=[]),
        findings=[],
        vulnerabilities=[],
        evidence=[],
        queries_executed=1,
        exact_versions_queried=1,
        advisories_count=0,
        affected_count=0,
        not_affected_count=0,
        unknown_count=0,
        osv_available=False,
        errors=["Network unreachable: connection timeout to OSV"],
    )

    with patch(
        "acsa.vulnerability.service.VulnerabilityService.scan_inventory",
        return_value=sample_result,
    ):
        result = runner.invoke(app, ["scan", "tests/fixtures/repo_basic"])
        assert result.exit_code == 0
        assert "OSV intelligence service was unavailable" in result.output
        assert "Network unreachable" in result.output
