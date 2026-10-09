"""ACSA Phase 5: Minimum-Blast-Radius Remediation Package."""

from acsa.remediation.candidates import CandidateGenerator, select_minimum_safe_version
from acsa.remediation.dependency_analysis import DependencyAnalyzer
from acsa.remediation.models import (
    CandidateStatus,
    ClosureStatus,
    DependencyContext,
    DependencyRelation,
    EvidenceConfidence,
    RemediationAnalysisResult,
    RemediationCandidate,
    RemediationDecision,
    RemediationReport,
    RemediationStrategy,
    RemediationVerificationSpec,
)
from acsa.remediation.ranking import RemediationRanker
from acsa.remediation.service import RemediationService

__all__ = [
    "CandidateGenerator",
    "CandidateStatus",
    "ClosureStatus",
    "DependencyAnalyzer",
    "DependencyContext",
    "DependencyRelation",
    "EvidenceConfidence",
    "RemediationAnalysisResult",
    "RemediationCandidate",
    "RemediationDecision",
    "RemediationRanker",
    "RemediationReport",
    "RemediationService",
    "RemediationStrategy",
    "RemediationVerificationSpec",
    "select_minimum_safe_version",
]
