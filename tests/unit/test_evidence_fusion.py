"""Unit tests for EvidenceFusionEngine validating explicit deterministic verdict rules."""

from acsa.context.models import AttackerControlStatus, ContextAnalysis, InputSource, InputSourceType
from acsa.evidence.models import EvidenceSource
from acsa.inventory.models import CanonicalInventory, Component, InventoryObservation
from acsa.reachability.models import ReachabilityAnalysis, ReachabilityState, SourceLocation
from acsa.verdict.fusion import EvidenceFusionEngine
from acsa.verdict.vocabulary import Verdict
from acsa.vulnerability.models import ApplicabilityStatus, Finding, Vulnerability


def test_fusion_rule_proven_exposure() -> None:
    """Rule: Affected + Reachable + Attacker Control Confirmed -> PROVEN_EXPOSURE."""
    vuln = Vulnerability(id="GHSA-test-1", summary="Flaw", vulnerable_symbols=["template"])
    comp = Component(name="lodash", version="4.17.19")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        applicability_status=ApplicabilityStatus.AFFECTED,
        reachability=ReachabilityAnalysis(
            status=ReachabilityState.REACHABLE,
            target_symbol="template",
            call_site="src/server.js:7",
        ),
        context=ContextAnalysis(
            status=AttackerControlStatus.CONFIRMED,
            source=InputSource(
                source_type=InputSourceType.BODY,
                expression="req.body.template",
                location=SourceLocation(file_path="src/server.js", line_number=6),
            ),
            entry_point="POST /render",
            sink="lodash.template()",
            data_flow_path=["POST /render", "req.body.template", "lodash.template()", "GHSA-test-1"],
        ),
    )
    inv = CanonicalInventory(components=[comp])
    engine = EvidenceFusionEngine()
    fused, _evidence, graph = engine.fuse(inv, [finding])

    assert len(fused) == 1
    assert fused[0].verdict == Verdict.PROVEN_EXPOSURE
    assert "reachable from application entry point and exposed" in (fused[0].notes or "")

    # Check EvidenceGraph full provenance path:
    # Artifact -> Component -> OSV -> Source -> HTTP -> Input -> Function -> Verdict
    verdict_node = graph.get_node(f"verdict:{finding.id}")
    assert verdict_node is not None
    assert verdict_node.label == "PROVEN_EXPOSURE"
    assert graph.has_path(f"comp:{comp.name}@{comp.version}", verdict_node.id)


def test_fusion_rule_potentially_affected() -> None:
    """Rule: Affected + Reachable + Attacker Control NOT Established -> POTENTIALLY_AFFECTED."""
    vuln = Vulnerability(id="GHSA-test-2", summary="Flaw", vulnerable_symbols=["template"])
    comp = Component(name="lodash", version="4.17.19")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        applicability_status=ApplicabilityStatus.AFFECTED,
        reachability=ReachabilityAnalysis(
            status=ReachabilityState.REACHABLE,
            target_symbol="template",
        ),
        context=ContextAnalysis(
            status=AttackerControlStatus.NOT_ESTABLISHED,
            uncertainty_reason="No external input established",
        ),
    )
    inv = CanonicalInventory(components=[comp])
    engine = EvidenceFusionEngine()
    fused, _ev, _graph = engine.fuse(inv, [finding])

    assert len(fused) == 1
    assert fused[0].verdict == Verdict.POTENTIALLY_AFFECTED


def test_fusion_rule_proven_affected() -> None:
    """Rule: Affected + Symbol NOT Reachable -> PROVEN_AFFECTED."""
    vuln = Vulnerability(id="GHSA-test-3", summary="Flaw", vulnerable_symbols=["template"])
    comp = Component(name="lodash", version="4.17.19")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        applicability_status=ApplicabilityStatus.AFFECTED,
        reachability=ReachabilityAnalysis(
            status=ReachabilityState.NOT_REACHABLE,
            target_symbol="template",
        ),
        context=ContextAnalysis(status=AttackerControlStatus.NOT_ESTABLISHED),
    )
    inv = CanonicalInventory(components=[comp])
    engine = EvidenceFusionEngine()
    fused, _ev, _graph = engine.fuse(inv, [finding])

    assert len(fused) == 1
    assert fused[0].verdict == Verdict.PROVEN_AFFECTED


def test_fusion_rule_unknown_dynamic_flow() -> None:
    """Rule: Affected + Reachability/Context UNKNOWN -> UNKNOWN (UNKNOWN != SAFE)."""
    vuln = Vulnerability(id="GHSA-test-4", summary="Flaw", vulnerable_symbols=["template"])
    comp = Component(name="lodash", version="4.17.19")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        applicability_status=ApplicabilityStatus.AFFECTED,
        reachability=ReachabilityAnalysis(
            status=ReachabilityState.REACHABLE,
            target_symbol="template",
        ),
        context=ContextAnalysis(
            status=AttackerControlStatus.UNKNOWN,
            uncertainty_reason="Dynamic property access prevents static determination",
        ),
    )
    inv = CanonicalInventory(components=[comp])
    engine = EvidenceFusionEngine()
    fused, _ev, _graph = engine.fuse(inv, [finding])

    assert len(fused) == 1
    assert fused[0].verdict == Verdict.UNKNOWN
    assert not fused[0].verdict.is_safe


def test_fusion_rule_proven_not_affected() -> None:
    """Rule: Version NOT Affected -> PROVEN_NOT_AFFECTED."""
    vuln = Vulnerability(id="GHSA-test-5", summary="Flaw", fixed_versions=["4.17.21"])
    comp = Component(name="lodash", version="4.17.21")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        applicability_status=ApplicabilityStatus.NOT_AFFECTED,
    )
    inv = CanonicalInventory(components=[comp])
    engine = EvidenceFusionEngine()
    fused, _ev, _graph = engine.fuse(inv, [finding])

    assert len(fused) == 1
    assert fused[0].verdict == Verdict.PROVEN_NOT_AFFECTED
    assert fused[0].verdict.is_safe


def test_fusion_rule_contradictory_inventory() -> None:
    """Rule: Multi-source conflicting versions producing conflicting security conclusions -> CONTRADICTORY."""
    vuln = Vulnerability(id="GHSA-test-6", summary="Flaw", affected_ranges=["< 4.17.21"])
    comp_lock = Component(name="lodash", version="4.17.21")
    comp_sbom = Component(name="lodash", version="4.17.19")

    obs1 = InventoryObservation(
        component_name="lodash",
        version="4.17.21",
        source_type=EvidenceSource.PACKAGE_LOCK,
        source_artifact_path="package-lock.json",
    )
    obs2 = InventoryObservation(
        component_name="lodash",
        version="4.17.19",
        source_type=EvidenceSource.CYCLONEDX_SBOM,
        source_artifact_path="sbom.json",
    )

    finding1 = Finding(
        vulnerability=vuln,
        component=comp_lock,
        applicability_status=ApplicabilityStatus.NOT_AFFECTED,
        source_artifact_path="package-lock.json",
    )
    finding2 = Finding(
        vulnerability=vuln,
        component=comp_sbom,
        applicability_status=ApplicabilityStatus.AFFECTED,
        source_artifact_path="sbom.json",
    )

    inv = CanonicalInventory(
        observations=[obs1, obs2],
        components=[comp_lock, comp_sbom],
    )

    engine = EvidenceFusionEngine()
    fused, evidence, _graph = engine.fuse(inv, [finding1, finding2])

    assert len(fused) == 2
    for f in fused:
        assert f.verdict == Verdict.CONTRADICTORY
        assert "Contradictory inventory observations" in (f.notes or "")
        assert "package-lock.json" in (f.notes or "")
        assert "sbom.json" in (f.notes or "")

    assert len(evidence) >= 1
    assert any("Contradictory inventory" in ev.description for ev in evidence)


def test_evidence_graph_complete_provenance_chain() -> None:
    """Validate that EvidenceGraph contains the complete provenance chain from artifact to verdict."""
    from acsa.context.models import DataFlowStep

    vuln = Vulnerability(id="GHSA-prov-1", summary="Flaw", vulnerable_symbols=["template"])
    comp = Component(name="lodash", version="4.17.19")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        source_artifact_path="package-lock.json",
        applicability_status=ApplicabilityStatus.AFFECTED,
        evidence_ids=["ev-test-1"],
        reachability=ReachabilityAnalysis(
            status=ReachabilityState.REACHABLE,
            target_symbol="template",
            call_site="src/server.js:7",
        ),
        context=ContextAnalysis(
            status=AttackerControlStatus.CONFIRMED,
            source=InputSource(
                source_type=InputSourceType.BODY,
                expression="req.body.template",
                location=SourceLocation(file_path="src/server.js", line_number=6),
            ),
            entry_point="POST /render",
            sink="lodash.template()",
            data_flow_steps=[
                DataFlowStep(
                    step_type="variable_assignment",
                    expression="const input = req.body.template",
                    description="Local assignment: const input = req.body.template",
                    location=SourceLocation(file_path="src/server.js", line_number=6),
                )
            ],
            data_flow_path=["POST /render", "req.body.template", "lodash.template()", "GHSA-prov-1"],
        ),
    )
    inv = CanonicalInventory(components=[comp])
    engine = EvidenceFusionEngine()
    fused, _ev, graph = engine.fuse(inv, [finding])

    assert len(fused) == 1
    assert fused[0].verdict == Verdict.PROVEN_EXPOSURE

    # Verify every link in the complete provenance chain exists
    art_id = "art:package-lock.json"
    comp_id = f"comp:{comp.name}@{comp.version}"
    osv_id = f"osv:{vuln.id}"
    sym_id = f"sym:{comp.name}.template"
    file_id = "file:src/server.js:6"
    http_id = "http:POST /render"
    input_id = "input:req.body.template"
    flow_id = "flow:const input = req.body.template"
    sink_id = "sink:lodash.template()"
    verdict_id = f"verdict:{finding.id}"

    for node_id in [art_id, comp_id, osv_id, sym_id, file_id, http_id, input_id, flow_id, sink_id, verdict_id]:
        assert node_id in graph.nodes, f"Missing node {node_id} in EvidenceGraph"
        node = graph.get_node(node_id)
        assert node is not None
        assert node.properties is not None

    # Verify end-to-end path from artifact to verdict
    assert graph.has_path(art_id, verdict_id)
    assert graph.has_path(comp_id, verdict_id)
    assert graph.has_path(osv_id, verdict_id)
    assert graph.has_path(input_id, verdict_id)


def test_missing_symbol_metadata_produces_unknown_verdict() -> None:
    """Regression test: missing symbol metadata produces UNKNOWN verdict; UNKNOWN != SAFE."""
    vuln = Vulnerability(id="GHSA-nosym-1", summary="Flaw without symbols", vulnerable_symbols=[])
    comp = Component(name="semver", version="5.7.0")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        source_artifact_path="package-lock.json",
        applicability_status=ApplicabilityStatus.AFFECTED,
        evidence_ids=["ev-nosym"],
        reachability=ReachabilityAnalysis(
            status=ReachabilityState.UNKNOWN,
            target_symbol=None,
            uncertainty_reason="Advisory provides no usable vulnerable symbol/function data",
            confidence=0.5,
        ),
    )
    inv = CanonicalInventory(components=[comp])
    engine = EvidenceFusionEngine()
    fused, _ev, _graph = engine.fuse(inv, [finding])

    assert len(fused) == 1
    f = fused[0]
    assert f.verdict == Verdict.UNKNOWN
    assert f.reachability is not None
    assert f.reachability.target_symbol is None
    assert "UNKNOWN != SAFE" in (f.notes or "")


def test_affected_but_not_reachable_produces_proven_affected_without_implying_exposure() -> None:
    """Regression test: affected component with unreachable symbol produces PROVEN_AFFECTED without implying exposure."""
    vuln = Vulnerability(id="GHSA-unreach-1", summary="Flaw", vulnerable_symbols=["template"])
    comp = Component(name="lodash", version="4.17.19")
    finding = Finding(
        vulnerability=vuln,
        component=comp,
        source_artifact_path="package-lock.json",
        applicability_status=ApplicabilityStatus.AFFECTED,
        evidence_ids=["ev-unreach"],
        reachability=ReachabilityAnalysis(
            status=ReachabilityState.NOT_REACHABLE,
            target_symbol="template",
            confidence=0.95,
        ),
    )
    inv = CanonicalInventory(components=[comp])
    engine = EvidenceFusionEngine()
    fused, _ev, _graph = engine.fuse(inv, [finding])

    assert len(fused) == 1
    f = fused[0]
    assert f.verdict == Verdict.PROVEN_AFFECTED
    # Must explicitly state installed version affected but not reachable, never implying exposure
    assert "installed version (4.17.19) is affected" in (f.notes or "")
    assert "proven not reachable" in (f.notes or "")
    assert "application exposure is not established" in (f.notes or "")


