"""Safe probe evaluation engine consuming structured empirical observations."""

import logging
from uuid import uuid4

from acsa.evidence.graph import EvidenceGraph
from acsa.evidence.models import EvidenceEdge, EvidenceNode
from acsa.probe.models import (
    ProbeEvaluation,
    ProbeEvaluationStatus,
    ProbeObservation,
    ProbeSpecification,
)
from acsa.verdict.vocabulary import Verdict

logger = logging.getLogger(__name__)


class ProbeEvaluator:
    """Evaluates external empirical observations against probe specifications without executing repository code."""

    @classmethod
    def evaluate(
        cls,
        probe: ProbeSpecification,
        observation: ProbeObservation,
        original_verdict: Verdict = Verdict.UNKNOWN,
        graph: EvidenceGraph | None = None,
    ) -> ProbeEvaluation:
        """Evaluate observation against probe specification and update the EvidenceGraph.

        Safety Guarantee:
        Never executes repository shell commands, npm scripts, or arbitrary code.
        Evaluates strictly against analyst- or runner-supplied structured telemetry.
        """
        # Validate probe match
        if observation.probe_id != probe.probe_id:
            logger.warning(
                "Observation probe_id '%s' does not match probe specification '%s'",
                observation.probe_id,
                probe.probe_id,
            )

        status: ProbeEvaluationStatus
        resolved_verdict: Verdict
        rationale: str

        if observation.observed is True:
            status = ProbeEvaluationStatus.CONFIRMED
            resolved_verdict = probe.expected_verdict_if_confirmed
            note = observation.observer_notes or "Empirical runtime evidence observed and verified"
            rationale = (
                f"Dynamic probe '{probe.probe_type.value}' CONFIRMED: {note}. "
                f"Verdict updated from {original_verdict.value} -> {resolved_verdict.value}."
            )
        elif observation.observed is False:
            status = ProbeEvaluationStatus.NOT_CONFIRMED
            resolved_verdict = probe.expected_verdict_if_not_confirmed
            note = observation.observer_notes or "Target runtime condition was not observed"
            rationale = (
                f"Dynamic probe '{probe.probe_type.value}' NOT_CONFIRMED: {note}. "
                f"Verdict updated from {original_verdict.value} -> {resolved_verdict.value}."
            )
        else:
            # observed is None or ambiguous
            status = ProbeEvaluationStatus.INCONCLUSIVE
            resolved_verdict = Verdict.UNKNOWN
            note = observation.observer_notes or "Telemetry incomplete or observation inconclusive"
            rationale = (
                f"Dynamic probe '{probe.probe_type.value}' INCONCLUSIVE: {note}. "
                f"Verdict remains {Verdict.UNKNOWN.value}."
            )

        # Generate evidence ID for provenance
        ev_id = str(uuid4())

        # Update EvidenceGraph if supplied
        if graph:
            cls._register_evaluation_in_graph(
                probe=probe,
                observation=observation,
                status=status,
                resolved_verdict=resolved_verdict,
                evidence_id=ev_id,
                graph=graph,
            )

        return ProbeEvaluation(
            probe_id=probe.probe_id,
            finding_id=probe.finding_id,
            evaluation_status=status,
            original_verdict=original_verdict,
            resolved_verdict=resolved_verdict,
            rationale=rationale,
            updated_evidence_ids=[ev_id],
        )

    @classmethod
    def _register_evaluation_in_graph(
        cls,
        probe: ProbeSpecification,
        observation: ProbeObservation,
        status: ProbeEvaluationStatus,
        resolved_verdict: Verdict,
        evidence_id: str,
        graph: EvidenceGraph,
    ) -> None:
        """Extend EvidenceGraph with OBSERVATION -> UPDATED_EVIDENCE provenance chain."""
        probe_node_id = f"probe_spec:{probe.probe_id}"
        obs_node_id = f"observation:{probe.probe_id}"
        ev_node_id = f"updated_evidence:{probe.probe_id}"

        # 1. Ensure probe node exists
        if not graph.get_node(probe_node_id):
            graph.add_node(
                EvidenceNode(
                    id=probe_node_id,
                    node_type="probe_specification",
                    label=f"PROBE_{probe.probe_type.value}: {probe.target_component}",
                    properties={"probe_id": probe.probe_id},
                )
            )

        # 2. Add OBSERVATION Node
        graph.add_node(
            EvidenceNode(
                id=obs_node_id,
                node_type="probe_observation",
                label=f"OBSERVATION: {status.value}",
                properties={
                    "probe_id": probe.probe_id,
                    "observed": str(observation.observed),
                    "status": status.value,
                    "payload_keys": list(observation.evidence_payload.keys()),
                },
            )
        )

        # Edge: PROBE_SPECIFICATION -> OBSERVATION
        graph.add_edge(
            EvidenceEdge(
                source=probe_node_id,
                target=obs_node_id,
                relationship="validated_by",
                properties={"status": status.value},
            )
        )

        # 3. Add UPDATED_EVIDENCE Node
        graph.add_node(
            EvidenceNode(
                id=ev_node_id,
                node_type="updated_evidence",
                label=f"EVIDENCE: {resolved_verdict.value}",
                properties={
                    "evidence_id": evidence_id,
                    "resolved_verdict": resolved_verdict.value,
                    "status": status.value,
                },
            )
        )

        # Edge: OBSERVATION -> UPDATED_EVIDENCE
        graph.add_edge(
            EvidenceEdge(
                source=obs_node_id,
                target=ev_node_id,
                relationship="yields",
                evidence_ids=[evidence_id],
                properties={"resolved_verdict": resolved_verdict.value},
            )
        )
