"""Unit tests for ACSA Phase 7 Uncertainty-Guided Dynamic Probe Planning."""

from acsa.context.models import AttackerControlStatus, ContextAnalysis, InputSource, InputSourceType
from acsa.evidence.graph import EvidenceGraph
from acsa.inventory.models import CanonicalInventory, Component
from acsa.probe.evaluator import ProbeEvaluator
from acsa.probe.models import (
    ProbeEvaluationStatus,
    ProbeObservation,
    ProbeType,
    SafetyConstraint,
)
from acsa.probe.planner import ProbePlanner
from acsa.reachability.models import ReachabilityAnalysis, ReachabilityState, SourceLocation
from acsa.verdict.vocabulary import Verdict
from acsa.vulnerability.models import (
    ApplicabilityStatus,
    Finding,
    Vulnerability,
    VulnerabilityScanResult,
)


def make_finding(
    component_name: str = "lodash",
    version: str = "4.17.19",
    target_symbol: str | None = None,
    entry_point: str | None = None,
    input_source_expr: str | None = None,
    uncertainty_reason: str = "Static analysis could not establish definitive data flow.",
    missing_evidence: str | None = None,
    verdict: Verdict = Verdict.UNKNOWN,
    severity: str = "HIGH",
    advisory_id: str = "GHSA-test-1234",
) -> Finding:
    """Helper creating a test Finding model with controlled uncertainty attributes."""
    comp = Component(name=component_name, version=version, ecosystem="npm")
    vuln = Vulnerability(
        id=advisory_id,
        summary="Test vulnerability",
        severity=severity,
    )

    reach = ReachabilityAnalysis(
        status=ReachabilityState.UNKNOWN,
        target_symbol=target_symbol,
        entry_point=entry_point,
        uncertainty_reason=uncertainty_reason,
        missing_evidence=missing_evidence,
    )

    ctx = None
    if input_source_expr or entry_point:
        src = None
        if input_source_expr:
            src = InputSource(
                source_type=InputSourceType.BODY,
                expression=input_source_expr,
                location=SourceLocation(file_path="routes/test.js", line_number=10),
                entry_point=entry_point,
            )
        ctx = ContextAnalysis(
            status=AttackerControlStatus.UNKNOWN,
            entry_point=entry_point,
            source=src,
            sink=target_symbol,
        )

    return Finding(
        vulnerability=vuln,
        component=comp,
        verdict=verdict,
        applicability_status=ApplicabilityStatus.AFFECTED,
        source_artifact_path="package.json",
        evidence_ids=[],
        confidence=0.5,
        reachability=reach,
        context=ctx,
        uncertainty_reason=uncertainty_reason,
        missing_evidence=missing_evidence,
    )


# -------------------------------------------------------------------------
# Test 1: Dynamic property / helper -> HTTP_INPUT_TO_SINK
# -------------------------------------------------------------------------
def test_dynamic_property_to_http_input_to_sink() -> None:
    """When an HTTP input and vulnerable sink exist with dynamic propagation, probe is HTTP_INPUT_TO_SINK."""
    finding = make_finding(
        component_name="lodash",
        target_symbol="template",
        entry_point="POST /render",
        input_source_expr="req.body.template",
        uncertainty_reason="Dynamic property access prevents static propagation through helper.",
    )

    spec = ProbePlanner.plan_for_finding(finding)
    assert spec is not None
    assert spec.probe_type == ProbeType.HTTP_INPUT_TO_SINK
    assert spec.target_component == "lodash"
    assert spec.target_symbol == "template"
    assert spec.entry_point == "POST /render"
    assert spec.input_source == "req.body.template"
    assert spec.expected_verdict_if_confirmed == Verdict.PROVEN_EXPOSURE
    assert spec.expected_verdict_if_not_confirmed == Verdict.PROVEN_AFFECTED
    assert SafetyConstraint.NO_UNTRUSTED_SCRIPTS.value in spec.safety_constraints


# -------------------------------------------------------------------------
# Test 2: Dynamic require -> MODULE_RESOLUTION
# -------------------------------------------------------------------------
def test_dynamic_require_to_module_resolution() -> None:
    """When static analysis encounters dynamic require, probe is MODULE_RESOLUTION."""
    finding = make_finding(
        component_name="unresolved-plugin",
        uncertainty_reason="Dynamic require(moduleName) prevents static import resolution.",
    )

    spec = ProbePlanner.plan_for_finding(finding)
    assert spec is not None
    assert spec.probe_type == ProbeType.MODULE_RESOLUTION
    assert spec.target_component == "unresolved-plugin"
    assert spec.expected_verdict_if_confirmed == Verdict.POTENTIALLY_AFFECTED
    assert spec.expected_verdict_if_not_confirmed == Verdict.PROVEN_NOT_AFFECTED


# -------------------------------------------------------------------------
# Test 3: Unknown symbol invocation -> SYMBOL_INVOCATION
# -------------------------------------------------------------------------
def test_unknown_symbol_invocation() -> None:
    """When a vulnerable symbol is identified but execution is unproven, probe is SYMBOL_INVOCATION."""
    finding = make_finding(
        component_name="serialize-javascript",
        target_symbol="serialize",
        uncertainty_reason="Static analysis could not establish whether serialize() executes.",
    )

    spec = ProbePlanner.plan_for_finding(finding)
    assert spec is not None
    assert spec.probe_type == ProbeType.SYMBOL_INVOCATION
    assert spec.target_component == "serialize-javascript"
    assert spec.target_symbol == "serialize"
    assert spec.expected_verdict_if_confirmed == Verdict.PROVEN_AFFECTED
    assert spec.expected_verdict_if_not_confirmed == Verdict.PROVEN_NOT_AFFECTED


# -------------------------------------------------------------------------
# Test 4: Dynamic route registration -> ROUTE_EXECUTION
# -------------------------------------------------------------------------
def test_dynamic_route_registration_to_route_execution() -> None:
    """When router uses dynamic registration (e.g. Express router), probe is ROUTE_EXECUTION."""
    finding = make_finding(
        component_name="express",
        entry_point="POST /login",
        uncertainty_reason="Dynamic route registration via app.use() prevents static route resolution.",
    )

    spec = ProbePlanner.plan_for_finding(finding)
    assert spec is not None
    assert spec.probe_type == ProbeType.ROUTE_EXECUTION
    assert spec.target_component == "express"
    assert spec.entry_point == "POST /login"
    assert spec.expected_verdict_if_confirmed == Verdict.PROVEN_AFFECTED
    assert spec.expected_verdict_if_not_confirmed == Verdict.PROVEN_NOT_AFFECTED


# -------------------------------------------------------------------------
# Test 5: Unknown dependency version -> DEPENDENCY_VERSION_CONFIRMATION
# -------------------------------------------------------------------------
def test_unknown_dependency_version_confirmation() -> None:
    """When lockfile resolution is incomplete or unregenerated, probe is DEPENDENCY_VERSION_CONFIRMATION."""
    finding = make_finding(
        component_name="minimist",
        uncertainty_reason="Unregenerated lockfile prevents exact dependency resolution confirmation.",
    )

    spec = ProbePlanner.plan_for_finding(finding)
    assert spec is not None
    assert spec.probe_type == ProbeType.DEPENDENCY_VERSION_CONFIRMATION
    assert spec.target_component == "minimist"
    assert spec.expected_verdict_if_confirmed == Verdict.PROVEN_AFFECTED
    assert spec.expected_verdict_if_not_confirmed == Verdict.NOT_VERIFIED


# -------------------------------------------------------------------------
# Test 6: Probe evaluation confirmed -> CONFIRMED & expected verdict
# -------------------------------------------------------------------------
def test_probe_evaluation_confirmed() -> None:
    """When observation confirms the probe condition, status is CONFIRMED and verdict transitions."""
    finding = make_finding(
        component_name="lodash",
        target_symbol="template",
        entry_point="POST /render",
        input_source_expr="req.body.template",
        uncertainty_reason="Dynamic helper propagation.",
    )
    spec = ProbePlanner.plan_for_finding(finding)
    assert spec is not None

    obs = ProbeObservation(
        probe_id=spec.probe_id,
        finding_id=spec.finding_id,
        observed=True,
        evidence_payload={"source": "req.body.template", "sink": "lodash.template", "route": "POST /render"},
        observer_notes="Observed runtime taint propagation into lodash.template",
    )

    evaluation = ProbeEvaluator.evaluate(probe=spec, observation=obs, original_verdict=Verdict.UNKNOWN)
    assert evaluation.evaluation_status == ProbeEvaluationStatus.CONFIRMED
    assert evaluation.original_verdict == Verdict.UNKNOWN
    assert evaluation.resolved_verdict == Verdict.PROVEN_EXPOSURE
    assert "CONFIRMED" in evaluation.rationale
    assert len(evaluation.updated_evidence_ids) > 0


# -------------------------------------------------------------------------
# Test 7: Probe evaluation not confirmed -> NOT_CONFIRMED & safe verdict
# -------------------------------------------------------------------------
def test_probe_evaluation_not_confirmed() -> None:
    """When observation demonstrates condition was not observed, status is NOT_CONFIRMED."""
    finding = make_finding(
        component_name="lodash",
        target_symbol="template",
        entry_point="POST /render",
        input_source_expr="req.body.template",
        uncertainty_reason="Dynamic helper propagation.",
    )
    spec = ProbePlanner.plan_for_finding(finding)
    assert spec is not None

    obs = ProbeObservation(
        probe_id=spec.probe_id,
        finding_id=spec.finding_id,
        observed=False,
        evidence_payload={"trace": "Request completed without reaching template()"},
        observer_notes="No invocation of lodash.template observed during 100 test runs",
    )

    evaluation = ProbeEvaluator.evaluate(probe=spec, observation=obs, original_verdict=Verdict.UNKNOWN)
    assert evaluation.evaluation_status == ProbeEvaluationStatus.NOT_CONFIRMED
    assert evaluation.resolved_verdict == Verdict.PROVEN_AFFECTED
    assert "NOT_CONFIRMED" in evaluation.rationale


# -------------------------------------------------------------------------
# Test 8: Inconclusive observation -> INCONCLUSIVE & UNKNOWN remains
# -------------------------------------------------------------------------
def test_probe_evaluation_inconclusive() -> None:
    """When observation is ambiguous or None, status is INCONCLUSIVE and verdict remains UNKNOWN."""
    finding = make_finding(
        component_name="lodash",
        target_symbol="template",
        entry_point="POST /render",
        input_source_expr="req.body.template",
        uncertainty_reason="Dynamic helper propagation.",
    )
    spec = ProbePlanner.plan_for_finding(finding)
    assert spec is not None

    obs = ProbeObservation(
        probe_id=spec.probe_id,
        finding_id=spec.finding_id,
        observed=None,
        evidence_payload={},
        observer_notes="Instrumentation timed out before trace completed",
    )

    evaluation = ProbeEvaluator.evaluate(probe=spec, observation=obs, original_verdict=Verdict.UNKNOWN)
    assert evaluation.evaluation_status == ProbeEvaluationStatus.INCONCLUSIVE
    assert evaluation.resolved_verdict == Verdict.UNKNOWN
    assert "INCONCLUSIVE" in evaluation.rationale


# -------------------------------------------------------------------------
# Test 9: No automatic probe execution occurs
# -------------------------------------------------------------------------
def test_no_probe_execution_occurs_automatically() -> None:
    """Verify that probe planner only produces specifications in PENDING state; no execution occurs."""
    finding = make_finding(
        component_name="lodash",
        target_symbol="template",
        entry_point="POST /render",
        input_source_expr="req.body.template",
    )
    scan_result = VulnerabilityScanResult(
        repository_path="d:/mock/repo",
        inventory=CanonicalInventory(),
        findings=[finding],
    )

    probes = ProbePlanner.plan_for_scan_result(scan_result)
    assert len(probes) == 1
    assert probes[0].status == ProbeEvaluationStatus.PENDING
    assert SafetyConstraint.EXPLICIT_EXECUTION_ONLY.value in probes[0].safety_constraints


# -------------------------------------------------------------------------
# Test 10: EvidenceGraph Provenance Chain
# -------------------------------------------------------------------------
def test_evidence_graph_provenance_chain() -> None:
    """Verify that graph preserves UNKNOWN -> MISSING_EVIDENCE -> PROBE_SPECIFICATION -> OBSERVATION -> UPDATED_EVIDENCE."""
    graph = EvidenceGraph()
    finding = make_finding(
        component_name="lodash",
        target_symbol="template",
        entry_point="POST /render",
        input_source_expr="req.body.template",
    )

    # 1. Plan probe with graph registration
    spec = ProbePlanner.plan_for_finding(finding, graph=graph)
    assert spec is not None

    unknown_id = f"verdict_unknown:{finding.id}"
    missing_id = f"missing_evidence:{spec.probe_id}"
    probe_id = f"probe_spec:{spec.probe_id}"

    assert graph.get_node(unknown_id) is not None
    assert graph.get_node(missing_id) is not None
    assert graph.get_node(probe_id) is not None
    assert graph.has_path(unknown_id, missing_id) is True
    assert graph.has_path(missing_id, probe_id) is True

    # 2. Evaluate observation with graph registration
    obs = ProbeObservation(
        probe_id=spec.probe_id,
        finding_id=spec.finding_id,
        observed=True,
        evidence_payload={"flow": "confirmed"},
    )
    ProbeEvaluator.evaluate(probe=spec, observation=obs, graph=graph)

    obs_id = f"observation:{spec.probe_id}"
    ev_id = f"updated_evidence:{spec.probe_id}"

    assert graph.get_node(obs_id) is not None
    assert graph.get_node(ev_id) is not None
    assert graph.has_path(probe_id, obs_id) is True
    assert graph.has_path(obs_id, ev_id) is True

    # Complete end-to-end provenance path exists
    assert graph.has_path(unknown_id, ev_id) is True


# -------------------------------------------------------------------------
# Test 11: Deterministic Probe Prioritization
# -------------------------------------------------------------------------
def test_deterministic_probe_prioritization() -> None:
    """Verify probes are ranked deterministically by criticality, proximity, and tie-breakers."""
    f1 = make_finding(
        component_name="b-component",
        severity="LOW",
        uncertainty_reason="Uncertainty low.",
        advisory_id="GHSA-low-001",
    )
    f2 = make_finding(
        component_name="a-component",
        severity="CRITICAL",
        target_symbol="sink_fn",
        entry_point="POST /api",
        input_source_expr="req.body.x",
        uncertainty_reason="Dynamic input flow.",
        advisory_id="GHSA-crit-002",
    )
    f3 = make_finding(
        component_name="c-component",
        severity="HIGH",
        target_symbol="exec",
        entry_point="GET /run",
        uncertainty_reason="Dynamic require(x).",
        advisory_id="GHSA-high-003",
    )

    scan_result = VulnerabilityScanResult(
        repository_path="d:/mock/repo",
        inventory=CanonicalInventory(),
        findings=[f1, f2, f3],
    )

    probes = ProbePlanner.plan_for_scan_result(scan_result)
    assert len(probes) == 3

    # CRITICAL finding with input+sink should rank #1
    assert probes[0].priority_rank == 1
    assert probes[0].target_component == "a-component"

    # HIGH finding should rank #2
    assert probes[1].priority_rank == 2
    assert probes[1].target_component == "c-component"

    # LOW finding should rank #3
    assert probes[2].priority_rank == 3
    assert probes[2].target_component == "b-component"
