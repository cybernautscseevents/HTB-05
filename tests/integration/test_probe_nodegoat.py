"""Integration tests for Phase 7 Uncertainty-Guided Dynamic Probe Planning on real OWASP NodeGoat."""

from pathlib import Path
from typing import Any

import pytest

from acsa.probe.models import (
    ProbeEvaluationStatus,
    ProbeObservation,
    ProbeType,
    SafetyConstraint,
)
from acsa.probe.service import ProbeService
from acsa.proof.service import RemediationProofService
from acsa.verdict.vocabulary import Verdict

NODEGOAT_PATH = (
    Path("tests/fixtures/nodegoat")
    if Path("tests/fixtures/nodegoat").exists()
    else Path(r"C:\Users\MEDHANAYAK\.gemini\antigravity-ide\brain\5e94201a-47d9-4532-b22c-bce95da9ad25\scratch\nodegoat")
)


@pytest.fixture(scope="module")
def nodegoat_scan_and_graph() -> tuple[Any, Any]:
    """Execute complete Phase 1-4 analysis once for the module on real OWASP NodeGoat."""
    scan_result, graph = RemediationProofService.run_full_analysis(NODEGOAT_PATH)
    return scan_result, graph


@pytest.mark.skipif(not NODEGOAT_PATH.exists(), reason="Real OWASP NodeGoat repository not cloned in scratch path")
def test_real_nodegoat_unknown_findings_generate_probes(nodegoat_scan_and_graph: Any) -> None:
    """Validate that real NodeGoat UNKNOWN findings generate concrete, actionable probe specifications.

    Demonstrates:
    - Multiple real findings in NodeGoat have UNKNOWN verdicts (e.g. dynamic router callbacks in express).
    - Probe planner produces actionable ProbeSpecification objects explaining why static analysis stopped.
    - Specifies required observation, missing evidence, and safety boundaries.
    - Probe status remains PENDING (no false or fabricated automated execution).
    """
    scan_result, graph = nodegoat_scan_and_graph

    report, updated_graph = ProbeService.plan_probes_for_repository(
        repository_path=NODEGOAT_PATH,
        scan_result=scan_result,
        graph=graph,
    )

    assert report.total_unknown_findings > 0
    assert report.total_probes_generated > 0
    assert len(report.probes) > 0

    # Locate Express probe
    express_probes = [p for p in report.probes if p.target_component == "express"]
    assert len(express_probes) > 0

    exp_probe = express_probes[0]
    assert exp_probe.probe_type in (
        ProbeType.ROUTE_EXECUTION,
        ProbeType.SYMBOL_INVOCATION,
        ProbeType.HTTP_INPUT_TO_SINK,
    )
    assert exp_probe.status == ProbeEvaluationStatus.PENDING

    # Detailed specifications present
    assert len(exp_probe.uncertainty_reason) > 0
    assert len(exp_probe.missing_evidence) > 0
    assert len(exp_probe.required_observation) > 0
    assert len(exp_probe.success_condition) > 0
    assert len(exp_probe.failure_condition) > 0

    # Defensive safety constraints enforced
    assert SafetyConstraint.NO_UNTRUSTED_SCRIPTS.value in exp_probe.safety_constraints
    assert SafetyConstraint.EXPLICIT_EXECUTION_ONLY.value in exp_probe.safety_constraints

    # Provenance registered in EvidenceGraph
    assert updated_graph.get_node(f"probe_spec:{exp_probe.probe_id}") is not None
    assert updated_graph.get_node(f"missing_evidence:{exp_probe.probe_id}") is not None


@pytest.mark.skipif(not NODEGOAT_PATH.exists(), reason="Real OWASP NodeGoat repository not cloned in scratch path")
def test_real_nodegoat_probe_safe_evaluation_flow(nodegoat_scan_and_graph: Any) -> None:
    """Validate safe empirical evaluation flow on a real NodeGoat probe specification.

    Demonstrates:
    - A structured observation is evaluated without running arbitrary repository code.
    - Evaluator transitions the UNKNOWN verdict to confirmed state based strictly on supplied evidence.
    """
    scan_result, graph = nodegoat_scan_and_graph

    report, _ = ProbeService.plan_probes_for_repository(
        repository_path=NODEGOAT_PATH,
        scan_result=scan_result,
        graph=graph,
    )

    exp_probe = next(p for p in report.probes if p.target_component == "express")

    # Supply an external observation
    obs = ProbeObservation(
        probe_id=exp_probe.probe_id,
        finding_id=exp_probe.finding_id,
        observed=True,
        evidence_payload={
            "dispatched_route": exp_probe.entry_point or "POST /login",
            "component": "express",
            "status": "handler_executed",
        },
        observer_notes="Observed via external test harness running instrumented container",
    )

    evaluation = ProbeService.evaluate_observation(
        probe=exp_probe,
        observation=obs,
        original_verdict=Verdict.UNKNOWN,
        graph=graph,
    )

    assert evaluation.evaluation_status == ProbeEvaluationStatus.CONFIRMED
    assert evaluation.original_verdict == Verdict.UNKNOWN
    assert evaluation.resolved_verdict == exp_probe.expected_verdict_if_confirmed
    assert "CONFIRMED" in evaluation.rationale
    assert len(evaluation.updated_evidence_ids) > 0
