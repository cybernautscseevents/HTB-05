"""Unit tests for Phase 6 Proof-Carrying Remediation and Machine-Verifiable Closure."""

from acsa.evidence.graph import EvidenceGraph
from acsa.evidence.models import EvidenceEdge, EvidenceNode
from acsa.proof.comparison import ProofComparisonEngine
from acsa.proof.models import (
    EvidenceSnapshot,
    TestValidationStatus,
    VerificationStatus,
)
from acsa.proof.verifier import ProofVerifier
from acsa.verdict.vocabulary import Verdict


def make_test_snapshot(
    phase: str,
    component: str = "lodash",
    version: str = "4.17.19",
    advisories: list[str] | None = None,
    verdict: Verdict = Verdict.PROVEN_EXPOSURE,
    applicability: dict[str, str] | None = None,
    vulnerable_symbols: list[str] | None = None,
    reachability_state: str = "REACHABLE",
    entry_points: list[str] | None = None,
    call_paths: list[list[str]] | None = None,
) -> EvidenceSnapshot:
    """Helper to create deterministic EvidenceSnapshot for testing."""
    adv_list = advisories if advisories is not None else ["GHSA-35jh-r3h4-6jhm"]
    app_map = applicability if applicability is not None else {adv_list[0]: "AFFECTED"}
    vuln_syms = vulnerable_symbols if vulnerable_symbols is not None else ["template"]
    eps = entry_points if entry_points is not None else ["POST /render"]

    return EvidenceSnapshot(
        phase=phase,
        repository_identity="/mock/repo",
        component=component,
        version=version,
        advisories=adv_list,
        verdict=verdict,
        vulnerability_applicability=app_map,
        vulnerable_symbols=vuln_syms,
        reachability_state=reachability_state,
        attacker_control_state="CONFIRMED" if verdict == Verdict.PROVEN_EXPOSURE else "NOT_ESTABLISHED",
        entry_points=eps,
        vulnerable_call_sites=[f"app.js:10 -> {vuln_syms[0]}"] if vuln_syms else [],
        call_paths=call_paths or [["POST /render", "req.body.tpl", vuln_syms[0]]] if vuln_syms else [],
        evidence_graph_digest="digest_test",
        evidence_ids=["ev-1"],
        source_locations=["app.js:10"],
        dependency_relation="DIRECT",
        manifest_version_constraint=f"^{version}",
        lockfile_version=version,
        lockfile_present=True,
    )


# -------------------------------------------------------------------------
# Test 1: Version becomes NOT_AFFECTED
# -------------------------------------------------------------------------
def test_version_becomes_not_affected() -> None:
    """Post-remediation version verified safe against advisories sets version_closed=True."""
    before = make_test_snapshot(phase="before", version="4.17.19", verdict=Verdict.PROVEN_EXPOSURE)
    after = make_test_snapshot(
        phase="after",
        version="4.17.21",
        verdict=Verdict.PROVEN_NOT_AFFECTED,
        applicability={"GHSA-35jh-r3h4-6jhm": "NOT_AFFECTED"},
        vulnerable_symbols=[],
        reachability_state="NOT_REACHABLE",
        call_paths=[],
    )

    comparison = ProofComparisonEngine.compare(before, after)
    conditions, status, _, _ = ProofVerifier.evaluate(before, after, comparison)

    assert conditions.version_closed is True
    assert conditions.advisories_closed is True
    assert status == VerificationStatus.PROVEN_REMEDIATED


# -------------------------------------------------------------------------
# Test 2: Advisory remains affected -> REMEDIATION_FAILED
# -------------------------------------------------------------------------
def test_advisory_remains_affected_fails() -> None:
    """If any advisory remains active in after state, verification fails."""
    before = make_test_snapshot(
        phase="before",
        advisories=["GHSA-1", "GHSA-2"],
        applicability={"GHSA-1": "AFFECTED", "GHSA-2": "AFFECTED"},
    )
    after = make_test_snapshot(
        phase="after",
        advisories=["GHSA-1", "GHSA-2"],
        # GHSA-2 is still AFFECTED!
        applicability={"GHSA-1": "NOT_AFFECTED", "GHSA-2": "AFFECTED"},
        verdict=Verdict.PROVEN_EXPOSURE,
    )

    comparison = ProofComparisonEngine.compare(before, after)
    conditions, status, reason, _ = ProofVerifier.evaluate(before, after, comparison)

    assert conditions.advisories_closed is False
    assert status == VerificationStatus.REMEDIATION_FAILED
    assert "GHSA-2" in str(reason)


# -------------------------------------------------------------------------
# Test 3: Vulnerable path disappears -> condition passes
# -------------------------------------------------------------------------
def test_vulnerable_path_disappears_passes() -> None:
    """When evidence graph shows previous exposure path is severed, exposure_path_closed passes."""
    before = make_test_snapshot(phase="before")
    after = make_test_snapshot(
        phase="after",
        version="4.17.21",
        verdict=Verdict.PROVEN_NOT_AFFECTED,
        applicability={"GHSA-35jh-r3h4-6jhm": "NOT_AFFECTED"},
        vulnerable_symbols=[],
        reachability_state="NOT_REACHABLE",
        call_paths=[],
    )

    before_graph = EvidenceGraph()
    before_graph.add_node(EvidenceNode(id="POST /render", label="Route", node_type="entry_point"))
    before_graph.add_node(EvidenceNode(id="template", label="Sink", node_type="vulnerable_symbol"))
    before_graph.add_edge(EvidenceEdge(source="POST /render", target="template", relationship="calls"))

    after_graph = EvidenceGraph()
    after_graph.add_node(EvidenceNode(id="POST /render", label="Route", node_type="entry_point"))
    # Note: no edge to template in after_graph!

    comparison = ProofComparisonEngine.compare(before, after, before_graph=before_graph, after_graph=after_graph)
    assert comparison.exposure_path_severed is True

    conditions, status, _, _ = ProofVerifier.evaluate(before, after, comparison)
    assert conditions.exposure_path_closed is True
    assert status == VerificationStatus.PROVEN_REMEDIATED


# -------------------------------------------------------------------------
# Test 4: Vulnerable path remains -> REMEDIATION_FAILED
# -------------------------------------------------------------------------
def test_vulnerable_path_remains_fails() -> None:
    """When after evidence graph still contains active attacker-controlled path, status is REMEDIATION_FAILED."""
    before = make_test_snapshot(phase="before")
    after = make_test_snapshot(
        phase="after",
        version="4.17.19",
        verdict=Verdict.PROVEN_EXPOSURE,
        applicability={"GHSA-35jh-r3h4-6jhm": "AFFECTED"},
        vulnerable_symbols=["template"],
        reachability_state="REACHABLE",
    )

    comparison = ProofComparisonEngine.compare(before, after)
    conditions, status, _, _ = ProofVerifier.evaluate(before, after, comparison)

    assert conditions.exposure_path_closed is False
    assert status == VerificationStatus.REMEDIATION_FAILED


# -------------------------------------------------------------------------
# Test 5: Before/after evidence conflict -> CONTRADICTORY
# -------------------------------------------------------------------------
def test_before_after_evidence_conflict_contradictory() -> None:
    """Conflicting or contradictory inventory observations yield CONTRADICTORY verification status."""
    before = make_test_snapshot(phase="before", verdict=Verdict.PROVEN_EXPOSURE)
    after = make_test_snapshot(phase="after", verdict=Verdict.CONTRADICTORY)

    comparison = ProofComparisonEngine.compare(before, after)
    _, status, reason, missing = ProofVerifier.evaluate(before, after, comparison)

    assert status == VerificationStatus.CONTRADICTORY
    assert "Contradictory" in str(reason)
    assert missing is not None


# -------------------------------------------------------------------------
# Test 6: Lockfile not regenerated -> REQUIRES_VERIFICATION
# -------------------------------------------------------------------------
def test_lockfile_not_regenerated_requires_verification() -> None:
    """In Mode A when lockfile was not regenerated, status MUST be REQUIRES_VERIFICATION."""
    before = make_test_snapshot(phase="before")
    after = make_test_snapshot(
        phase="after",
        version="4.17.21",
        verdict=Verdict.PROVEN_NOT_AFFECTED,
        applicability={"GHSA-35jh-r3h4-6jhm": "NOT_AFFECTED"},
        vulnerable_symbols=[],
        reachability_state="NOT_REACHABLE",
        call_paths=[],
    )

    comparison = ProofComparisonEngine.compare(before, after)
    conditions, status, reason, missing = ProofVerifier.evaluate(
        before, after, comparison, lockfile_not_regenerated=True
    )

    assert conditions.version_closed is False  # Cannot confirm installed version without lockfile
    assert status == VerificationStatus.REQUIRES_VERIFICATION
    assert "lockfile regeneration" in str(reason).lower()
    assert "package-lock.json" in str(missing)


# -------------------------------------------------------------------------
# Test 7: Unknown reachability after remediation -> REQUIRES_VERIFICATION
# -------------------------------------------------------------------------
def test_unknown_reachability_requires_verification() -> None:
    """When post-remediation reachability remains UNKNOWN, status is REQUIRES_VERIFICATION."""
    before = make_test_snapshot(phase="before")
    after = make_test_snapshot(
        phase="after",
        version="4.17.21",
        verdict=Verdict.UNKNOWN,
        reachability_state="UNKNOWN",
        applicability={"GHSA-35jh-r3h4-6jhm": "NOT_AFFECTED"},
    )

    comparison = ProofComparisonEngine.compare(before, after)
    _, status, reason, missing = ProofVerifier.evaluate(before, after, comparison)

    assert status == VerificationStatus.REQUIRES_VERIFICATION
    assert "UNKNOWN" in str(reason)
    assert missing is not None


# -------------------------------------------------------------------------
# Test 8: All required conditions pass -> PROVEN_REMEDIATED
# -------------------------------------------------------------------------
def test_all_required_conditions_pass_proven_remediated() -> None:
    """When all 4 required closure conditions are satisfied, status is PROVEN_REMEDIATED."""
    before = make_test_snapshot(phase="before", version="4.16.4", verdict=Verdict.PROVEN_EXPOSURE)
    after = make_test_snapshot(
        phase="after",
        version="4.20.0",
        verdict=Verdict.PROVEN_NOT_AFFECTED,
        applicability={"GHSA-35jh-r3h4-6jhm": "NOT_AFFECTED"},
        vulnerable_symbols=[],
        reachability_state="NOT_REACHABLE",
        call_paths=[],
    )

    comparison = ProofComparisonEngine.compare(before, after)
    conditions, status, reason, missing = ProofVerifier.evaluate(before, after, comparison)

    assert conditions.version_closed is True
    assert conditions.advisories_closed is True
    assert conditions.vulnerable_symbol_closed is True
    assert conditions.exposure_path_closed is True
    assert status == VerificationStatus.PROVEN_REMEDIATED
    assert reason is None
    assert missing is None


# -------------------------------------------------------------------------
# Test 9: Tests not executed vs failed
# -------------------------------------------------------------------------
def test_tests_not_executed_policy_preserves_proven_remediated() -> None:
    """When test execution is disabled by policy, conditions 1-4 are independently sufficient.

    If tests fail, status becomes REMEDIATION_FAILED.
    """
    before = make_test_snapshot(phase="before", version="4.16.4", verdict=Verdict.PROVEN_EXPOSURE)
    after = make_test_snapshot(
        phase="after",
        version="4.20.0",
        verdict=Verdict.PROVEN_NOT_AFFECTED,
        applicability={"GHSA-35jh-r3h4-6jhm": "NOT_AFFECTED"},
        vulnerable_symbols=[],
        reachability_state="NOT_REACHABLE",
        call_paths=[],
    )
    comparison = ProofComparisonEngine.compare(before, after)

    # 1. Tests NOT_EXECUTED by policy
    conds1, status1, _, _ = ProofVerifier.evaluate(
        before,
        after,
        comparison,
        test_status=TestValidationStatus.NOT_EXECUTED,
        test_reason="Repository command execution disabled by security policy.",
    )
    assert conds1.tests_validated is False
    assert conds1.test_status == TestValidationStatus.NOT_EXECUTED
    assert status1 == VerificationStatus.PROVEN_REMEDIATED

    # 2. Tests FAILED
    conds2, status2, reason2, _ = ProofVerifier.evaluate(
        before,
        after,
        comparison,
        test_status=TestValidationStatus.FAILED,
        test_reason="npm test exited with code 1",
    )
    assert conds2.tests_validated is False
    assert status2 == VerificationStatus.REMEDIATION_FAILED
    assert "tests failed" in str(reason2).lower()
