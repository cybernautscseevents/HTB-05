"""Integration tests for Phase 6 Proof-Carrying Remediation on real repository (OWASP NodeGoat)."""

from pathlib import Path
from typing import Any

import pytest

from acsa.proof.models import VerificationMode, VerificationStatus
from acsa.proof.service import RemediationProofService
from acsa.remediation.service import RemediationService

NODEGOAT_PATH = (
    Path("tests/fixtures/nodegoat")
    if Path("tests/fixtures/nodegoat").exists()
    else Path(r"C:\Users\MEDHANAYAK\.gemini\antigravity-ide\brain\5e94201a-47d9-4532-b22c-bce95da9ad25\scratch\nodegoat")
)


@pytest.fixture(scope="module")
def nodegoat_analysis_and_express_candidate() -> tuple[Any, Any, Any, Any]:
    """Precompute NodeGoat analysis and express candidate once for the module."""
    scan_result, graph = RemediationProofService.run_full_analysis(NODEGOAT_PATH)
    express_findings = [f for f in scan_result.findings if f.component.name == "express"]
    assert len(express_findings) > 0
    exp_finding = express_findings[0]

    rem_report = RemediationService().remediate_repository(NODEGOAT_PATH, scan_result)
    express_rem = [r for r in rem_report.results if r.package_name == "express" and r.selected_candidate]
    assert len(express_rem) > 0
    exp_candidate = express_rem[0].selected_candidate

    return scan_result, graph, exp_finding, exp_candidate


@pytest.mark.skipif(not NODEGOAT_PATH.exists(), reason="Real OWASP NodeGoat repository not cloned in scratch path")
def test_real_nodegoat_express_verification_mode_a(nodegoat_analysis_and_express_candidate: Any) -> None:
    """Validate real OWASP NodeGoat Express remediation under Mode A (simulated).

    Demonstrates:
    - Candidate: express 4.16.4 -> 4.20.0
    - Lockfile regeneration is NOT executed to avoid running untrusted scripts
    - Verification status MUST be REQUIRES_VERIFICATION (no false claims of PROVEN_REMEDIATED)
    - Missing evidence explicitly guides developer to run `npm install --package-lock-only`
    """
    _, graph, exp_finding, exp_cand = nodegoat_analysis_and_express_candidate

    proof = RemediationProofService.verify_candidate(
        repository_path=NODEGOAT_PATH,
        finding=exp_finding,
        candidate=exp_cand,
        mode=VerificationMode.MODE_A_SIMULATED,
        before_graph=graph,
    )

    assert proof.target_component == "express"
    assert proof.before_snapshot.version == "4.16.4"
    assert proof.strategy == "DIRECT_UPGRADE"

    # Crucial assertion: never falsely claim PROVEN_REMEDIATED when lockfile is not regenerated
    assert proof.verification_status == VerificationStatus.REQUIRES_VERIFICATION
    assert proof.conditions.version_closed is False
    assert "package-lock.json" in str(proof.missing_evidence)


@pytest.mark.skipif(not NODEGOAT_PATH.exists(), reason="Real OWASP NodeGoat repository not cloned in scratch path")
def test_real_nodegoat_express_verification_mode_b(nodegoat_analysis_and_express_candidate: Any) -> None:
    """Validate real OWASP NodeGoat Express remediation under Mode B (materialized dependency).

    Demonstrates:
    - Post-remediation version 4.20.0 is materialized in isolated workspace
    - Live OSV intelligence verifies that 4.20.0 is NOT_AFFECTED by GHSA-qw6h-vgh9-j6wx and GHSA-rv95-896h-c2vc
    - Advisories condition passes (2/2 resolved)
    - However, because express middleware dispatch in NodeGoat has UNKNOWN static reachability,
      the system does NOT falsely claim PROVEN_REMEDIATED; it preserves uncertainty with REQUIRES_VERIFICATION.
    """
    _, graph, exp_finding, exp_cand = nodegoat_analysis_and_express_candidate

    proof = RemediationProofService.verify_candidate(
        repository_path=NODEGOAT_PATH,
        finding=exp_finding,
        candidate=exp_cand,
        mode=VerificationMode.MODE_B_MATERIALIZED,
        before_graph=graph,
    )

    assert proof.target_component == "express"
    assert proof.before_snapshot.version == "4.16.4"
    assert proof.after_snapshot.version == "4.20.0"

    # Both advisories are resolved by OSV in 4.20.0
    assert proof.conditions.advisories_closed is True
    assert proof.conditions.version_closed is True
    assert proof.conditions.vulnerable_symbol_closed is True
    assert proof.conditions.exposure_path_closed is False  # Cannot prove path severance when pre-remediation path was UNKNOWN

    # Crucial safety guarantee: The system does NOT falsely claim PROVEN_REMEDIATED.
    # Because exposure path closure cannot be verified, status is REMEDIATION_PARTIALLY_VERIFIED.
    assert proof.verification_status is VerificationStatus.REMEDIATION_PARTIALLY_VERIFIED
    assert proof.uncertainty_reason is not None
    assert "partially verified" in proof.uncertainty_reason.lower()
