"""Coordinating service for Uncertainty-Guided Dynamic Probe Planning."""

import logging
from collections import Counter
from pathlib import Path

from acsa.context.models import AttackerControlStatus
from acsa.evidence.graph import EvidenceGraph
from acsa.probe.evaluator import ProbeEvaluator
from acsa.probe.models import (
    ProbeEvaluation,
    ProbeObservation,
    ProbePlanReport,
    ProbeSpecification,
)
from acsa.probe.planner import ProbePlanner
from acsa.proof.service import RemediationProofService
from acsa.reachability.models import ReachabilityState
from acsa.verdict.vocabulary import Verdict
from acsa.vulnerability.models import VulnerabilityScanResult

logger = logging.getLogger(__name__)


class ProbeService:
    """Orchestrates dynamic probe generation and safe empirical evaluation."""

    @classmethod
    def plan_probes_for_repository(
        cls,
        repository_path: Path | str,
        scan_result: VulnerabilityScanResult | None = None,
        graph: EvidenceGraph | None = None,
    ) -> tuple[ProbePlanReport, EvidenceGraph]:
        """Analyze repository findings, identify evidence gaps, and produce prioritized probe specifications."""
        repo_dir = Path(repository_path)

        # 1. Run full analysis if not already supplied
        if scan_result is None or graph is None:
            scan_result, graph = RemediationProofService.run_full_analysis(repo_dir)

        # 2. Plan probes across findings
        probes = ProbePlanner.plan_for_scan_result(scan_result, graph=graph)

        # 3. Compute metrics
        unknown_findings_count = sum(
            1
            for f in scan_result.findings
            if (
                f.verdict == Verdict.UNKNOWN
                or (f.reachability and f.reachability.status == ReachabilityState.UNKNOWN)
                or (f.context and f.context.status == AttackerControlStatus.UNKNOWN)
                or bool(f.uncertainty_reason)
            )
        )

        type_counts = Counter(p.probe_type.value for p in probes)

        summary = (
            f"Generated {len(probes)} targeted dynamic probe specifications across "
            f"{unknown_findings_count} uncertain findings. Top recommended probes: "
            f"{', '.join(f'{k}: {v}' for k, v in type_counts.most_common(3))}."
        )

        report = ProbePlanReport(
            repository_path=str(repo_dir),
            total_unknown_findings=unknown_findings_count,
            total_probes_generated=len(probes),
            probes_by_type=dict(type_counts),
            probes=probes,
            summary=summary,
        )

        return report, graph

    @classmethod
    def evaluate_observation(
        cls,
        probe: ProbeSpecification,
        observation: ProbeObservation,
        original_verdict: Verdict = Verdict.UNKNOWN,
        graph: EvidenceGraph | None = None,
    ) -> ProbeEvaluation:
        """Evaluate an empirical observation against a probe specification without executing code."""
        return ProbeEvaluator.evaluate(
            probe=probe,
            observation=observation,
            original_verdict=original_verdict,
            graph=graph,
        )
