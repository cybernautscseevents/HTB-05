"""Domain models for post-remediation verification and proof-carrying artifacts."""

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from acsa.verdict.vocabulary import Verdict


class VerificationResult(BaseModel):
    """Result of re-analyzing an artifact after applying a candidate remediation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique verification ID")
    finding_id: str = Field(description="Target finding being verified")
    candidate_id: str = Field(description="Remediation candidate applied during test")
    prior_verdict: Verdict = Field(
        description="Verdict before remediation (e.g. PROVEN_EXPOSURE)"
    )
    post_verdict: Verdict = Field(
        description="Verdict after remediation (e.g. PROVEN_NOT_AFFECTED)"
    )
    path_closed: bool = Field(
        description="Whether the previously proven exposure path was successfully severed"
    )
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="Evidence objects produced during post-remediation analysis",
    )
    executed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of verification execution",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Diagnostic details, test results, and call path delta",
    )


class ProofArtifact(BaseModel):
    """Novelty 1: Proof-Carrying Remediation artifact.

    Cryptographically verifiable evidence bundle embedded in remediation pull requests
    demonstrating that exposure paths were demonstrably closed without introducing regressions.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique proof artifact ID")
    verification_result_id: str = Field(description="Associated verification result ID")
    before_evidence_graph_digest: str = Field(
        description="Cryptographic SHA-256 digest of pre-remediation evidence graph"
    )
    after_evidence_graph_digest: str = Field(
        description="Cryptographic SHA-256 digest of post-remediation evidence graph"
    )
    execution_log_digest: str | None = Field(
        default=None,
        description="Optional digest of verification test execution trace",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when proof was generated",
    )
    proof_summary: str = Field(
        description="Executive and technical summary of why this remediation is proven to work"
    )
    is_verified: bool = Field(
        default=True,
        description="Cryptographic and logical validity status of the proof",
    )
