"""Service orchestrating evidence fusion, contradiction reconciliation, and final verdicts."""

import logging
from typing import TYPE_CHECKING

from acsa.evidence.graph import EvidenceGraph
from acsa.evidence.models import Evidence
from acsa.inventory.models import CanonicalInventory
from acsa.verdict.fusion import EvidenceFusionEngine
from acsa.verdict.vocabulary import Verdict

if TYPE_CHECKING:
    from acsa.vulnerability.models import Finding, VulnerabilityScanResult

logger = logging.getLogger(__name__)


class EvidenceFusionService:
    """Orchestrates Phase 4 multi-source evidence fusion and verdict determination."""

    def __init__(self, engine: EvidenceFusionEngine | None = None) -> None:
        self.engine = engine or EvidenceFusionEngine()

    def fuse_findings(
        self,
        inventory: CanonicalInventory,
        findings: list["Finding"],
        graph: EvidenceGraph | None = None,
    ) -> tuple[list["Finding"], list[Evidence], EvidenceGraph]:
        """Execute evidence fusion across inventory, vulnerability, reachability, and context evidence."""
        return self.engine.fuse(inventory=inventory, findings=findings, graph=graph)

    def enrich_scan_result(
        self,
        scan_result: "VulnerabilityScanResult",
        graph: EvidenceGraph | None = None,
    ) -> "VulnerabilityScanResult":
        """Enrich a VulnerabilityScanResult with fused verdicts and Phase 4 metrics."""
        fused_findings, fusion_evidence, _extended_graph = self.fuse_findings(
            inventory=scan_result.inventory,
            findings=scan_result.findings,
            graph=graph,
        )

        all_evidence = list(scan_result.evidence) + fusion_evidence

        # Compute authoritative Phase 4 verdict metrics
        proven_exposure = sum(1 for f in fused_findings if f.verdict == Verdict.PROVEN_EXPOSURE)
        proven_affected = sum(1 for f in fused_findings if f.verdict == Verdict.PROVEN_AFFECTED)
        potentially_affected = sum(
            1 for f in fused_findings if f.verdict == Verdict.POTENTIALLY_AFFECTED
        )
        proven_not_affected = sum(
            1 for f in fused_findings if f.verdict == Verdict.PROVEN_NOT_AFFECTED
        )
        contradictory = sum(1 for f in fused_findings if f.verdict == Verdict.CONTRADICTORY)
        unknown = sum(1 for f in fused_findings if f.verdict == Verdict.UNKNOWN)

        return scan_result.model_copy(
            update={
                "findings": fused_findings,
                "evidence": all_evidence,
                "context_evaluated": True,
                "fusion_evaluated": True,
                "proven_exposure_count": proven_exposure,
                "proven_affected_count": proven_affected,
                "potentially_affected_count": potentially_affected,
                "proven_not_affected_count": proven_not_affected,
                "contradictory_count": contradictory,
                "unknown_count": unknown,
            }
        )
