"""ACSA — Artifact-Centric Security Analysis.

Evidence-driven software supply chain security for JavaScript/TypeScript and npm ecosystems.
Don't just detect vulnerabilities. Prove their exposure.
"""

from acsa.evidence.graph import EvidenceGraph
from acsa.evidence.models import Evidence, EvidenceEdge, EvidenceNode, EvidenceSource
from acsa.ingestion.models import Repository, RepositorySnapshot
from acsa.inventory.models import Component, Contradiction, Dependency, TrustAssessment
from acsa.remediation.models import RemediationCandidate, RemediationDecision
from acsa.verdict.vocabulary import Verdict
from acsa.verification.models import ProofArtifact, VerificationResult
from acsa.vulnerability.models import Finding, Vulnerability

__version__ = "0.1.0"

__all__ = [
    "Component",
    "Contradiction",
    "Dependency",
    "Evidence",
    "EvidenceEdge",
    "EvidenceGraph",
    "EvidenceNode",
    "EvidenceSource",
    "Finding",
    "ProofArtifact",
    "RemediationCandidate",
    "RemediationDecision",
    "Repository",
    "RepositorySnapshot",
    "TrustAssessment",
    "Verdict",
    "VerificationResult",
    "Vulnerability",
]
