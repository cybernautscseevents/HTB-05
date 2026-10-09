"""Integration test validating Minimum-Blast-Radius remediation against real repository findings (OWASP NodeGoat)."""

from pathlib import Path

import pytest

from acsa.ingestion.service import IngestionService
from acsa.remediation.models import CandidateStatus, DependencyRelation, RemediationStrategy
from acsa.remediation.service import RemediationService
from acsa.vulnerability.service import VulnerabilityService

NODEGOAT_PATH = (
    Path("tests/fixtures/nodegoat")
    if Path("tests/fixtures/nodegoat").exists()
    else Path(r"C:\Users\MEDHANAYAK\.gemini\antigravity-ide\brain\5e94201a-47d9-4532-b22c-bce95da9ad25\scratch\nodegoat")
)


@pytest.mark.skipif(not NODEGOAT_PATH.exists(), reason="Real OWASP NodeGoat repository not cloned in scratch path")
def test_real_nodegoat_remediation_candidate_generation() -> None:
    """Validate remediation candidate generation on real OWASP NodeGoat repository.

    Demonstrates:
    - Real package: express / marked / semver
    - Real OSV advisories
    - Real target safe versions
    - Minimum blast radius selection
    - Simulated in-memory patch
    """
    ingest_service = IngestionService()
    ingest_result = ingest_service.ingest_repository(NODEGOAT_PATH)

    vuln_service = VulnerabilityService()
    scan_result = vuln_service.scan_inventory(ingest_result.inventory, repository_path=str(NODEGOAT_PATH))

    assert len(scan_result.findings) > 0

    rem_service = RemediationService()
    rem_report = rem_service.remediate_repository(NODEGOAT_PATH, scan_result)

    assert rem_report.total_findings_evaluated > 0
    assert rem_report.remediated_findings_count > 0

    # 1. Inspect direct findings (e.g. express or marked)
    express_results = [r for r in rem_report.results if r.package_name == "express"]
    if express_results:
        exp_res = express_results[0]
        assert exp_res.dependency_relation == DependencyRelation.DIRECT
        assert exp_res.selected_candidate is not None
        assert exp_res.selected_candidate.strategy == RemediationStrategy.DIRECT_UPGRADE
        assert exp_res.selected_candidate.target_version == "4.20.0"  # Minimum safe resolving all advisories
        assert exp_res.selected_candidate.lockfile_action == "LOCKFILE_REGENERATION_REQUIRED"
        assert exp_res.selected_candidate.status in (CandidateStatus.ACCEPTED, CandidateStatus.PROPOSED, CandidateStatus.REQUIRES_CONFIRMATION)
        assert exp_res.selected_candidate.simulated_patch is not None
        assert "package.json" in exp_res.selected_candidate.simulated_patch
        assert "LOCKFILE_REGENERATION_REQUIRED" in exp_res.selected_candidate.simulated_patch
        assert exp_res.blast_radius_explanation != ""

    # 2. Inspect non-contradictory transitive finding (e.g. adm-zip)
    adm_results = [r for r in rem_report.results if r.package_name == "adm-zip"]
    if adm_results:
        adm_res = adm_results[0]
        assert adm_res.dependency_relation == DependencyRelation.TRANSITIVE
        assert adm_res.parent_package == "selenium-webdriver"
        assert adm_res.selected_candidate is not None
        assert adm_res.selected_candidate.strategy in (RemediationStrategy.TRANSITIVE_OVERRIDE, RemediationStrategy.PARENT_UPGRADE)
        assert adm_res.selected_candidate.simulated_patch is not None
        assert "package.json" in adm_res.selected_candidate.simulated_patch

    # 3. Inspect contradictory transitive finding (semver has multiple versions across lockfile)
    semver_results = [r for r in rem_report.results if r.package_name == "semver"]
    if semver_results:
        sem_res = semver_results[0]
        assert sem_res.dependency_relation == DependencyRelation.TRANSITIVE
        # Safe contradiction blocking prevents blind automated recommendation
        assert sem_res.selected_candidate is None
        assert any(c.status == CandidateStatus.CONTRADICTION_BLOCKED for c in sem_res.candidates)
