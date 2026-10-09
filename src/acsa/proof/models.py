"""Domain models for Phase 6 Proof-Carrying Remediation and Machine-Verifiable Closure."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from acsa.verdict.vocabulary import Verdict


class VerificationStatus(StrEnum):
    """Authoritative result state for post-remediation verification."""

    PROVEN_REMEDIATED = "PROVEN_REMEDIATED"
    """All required machine-verifiable closure conditions are strictly satisfied by AFTER evidence."""

    REMEDIATION_PARTIALLY_VERIFIED = "REMEDIATION_PARTIALLY_VERIFIED"
    """Some conditions pass, but at least one required condition cannot be verified."""

    REQUIRES_VERIFICATION = "REQUIRES_VERIFICATION"
    """Required evidence is unavailable (e.g. lockfile not regenerated, reachability unknown)."""

    REMEDIATION_FAILED = "REMEDIATION_FAILED"
    """Candidate was applied and re-analyzed, but vulnerability or exposure path remains active."""

    CONTRADICTORY = "CONTRADICTORY"
    """Before/after evidence conflicts in a way that prevents a trustworthy conclusion."""

    NOT_VERIFIED = "NOT_VERIFIED"
    """Insufficient evidence available to begin or complete verification."""


class VerificationMode(StrEnum):
    """Operating mode for remediation verification workspace execution."""

    MODE_A_SIMULATED = "MODE_A_SIMULATED"
    """Static/simulated verification where lockfile regeneration is not executed for safety."""

    MODE_B_MATERIALIZED = "MODE_B_MATERIALIZED"
    """Materialized verification in a workspace containing the intended post-remediation dependency state."""


class TestValidationStatus(StrEnum):
    """Execution status of repository test suites or build validations."""

    __test__ = False

    PASSED = "PASSED"
    """Test suite executed and passed cleanly without regressions."""

    FAILED = "FAILED"
    """Test suite failed or reported regressions after applying candidate."""

    NOT_EXECUTED = "NOT_EXECUTED"
    """Test execution was disabled by ACSA security policy to prevent running untrusted code."""


class ProofConditions(BaseModel):
    """Explicit, machine-verifiable closure conditions evaluated between BEFORE and AFTER states."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    version_closed: bool = Field(
        description="Whether the component version in AFTER state is verified non-vulnerable / NOT_AFFECTED"
    )
    advisories_closed: bool = Field(
        description="Whether all relevant advisories associated with the component are completely resolved"
    )
    vulnerable_symbol_closed: bool = Field(
        description="Whether the previously reachable vulnerable symbol is eliminated or unreachable"
    )
    exposure_path_closed: bool = Field(
        description="Whether the previously proven attacker-to-vulnerable-symbol path was severed in the evidence graph"
    )
    tests_validated: bool = Field(
        default=False,
        description="Whether repository tests passed post-remediation (False if not executed)",
    )
    test_status: TestValidationStatus = Field(
        default=TestValidationStatus.NOT_EXECUTED,
        description="Test execution outcome under safe execution policy",
    )
    test_reason: str | None = Field(
        default="Repository command execution disabled by security policy.",
        description="Explanation for test execution status",
    )


class EvidenceSnapshot(BaseModel):
    """Machine-readable, immutable state snapshot of a component finding before or after remediation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    phase: str = Field(description="Snapshot phase: 'before' or 'after'")
    repository_identity: str = Field(description="Repository path or unique identifier")
    component: str = Field(description="Target component / package name")
    version: str | None = Field(default=None, description="Exact installed or resolved version")
    advisories: list[str] = Field(
        default_factory=list,
        description="IDs of advisories evaluated against this component",
    )
    verdict: Verdict = Field(description="ACSA verdict for this component finding")
    vulnerability_applicability: dict[str, str] = Field(
        default_factory=dict,
        description="Advisory ID to applicability determination (AFFECTED, NOT_AFFECTED, UNKNOWN)",
    )
    vulnerable_symbols: list[str] = Field(
        default_factory=list,
        description="Symbols identified as vulnerable by advisory intelligence",
    )
    reachability_state: str = Field(
        default="UNKNOWN",
        description="Static reachability state: REACHABLE, NOT_REACHABLE, or UNKNOWN",
    )
    attacker_control_state: str = Field(
        default="UNKNOWN",
        description="Attacker control classification: CONFIRMED, NOT_ESTABLISHED, or UNKNOWN",
    )
    entry_points: list[str] = Field(
        default_factory=list,
        description="HTTP or application entry points reaching this component",
    )
    vulnerable_call_sites: list[str] = Field(
        default_factory=list,
        description="Source code locations where vulnerable symbols are invoked",
    )
    call_paths: list[list[str]] = Field(
        default_factory=list,
        description="Call graph and data flow propagation paths",
    )
    evidence_graph_digest: str = Field(
        default="",
        description="Cryptographic SHA-256 digest of the evidence graph",
    )
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="IDs of evidence objects associated with this finding",
    )
    source_locations: list[str] = Field(
        default_factory=list,
        description="Source file locations involved in the finding",
    )
    dependency_relation: str = Field(
        default="DIRECT",
        description="Classification: DIRECT, TRANSITIVE, UNUSED, or UNKNOWN",
    )
    manifest_version_constraint: str | None = Field(
        default=None,
        description="Declared version constraint in manifest (e.g. ^4.16.4)",
    )
    lockfile_version: str | None = Field(
        default=None,
        description="Exact installed version recorded in lockfile",
    )
    lockfile_present: bool = Field(
        default=True,
        description="Whether a lockfile was discovered in the repository",
    )
    details: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional technical telemetry or AST attributes",
    )


class ProofComparison(BaseModel):
    """Detailed delta and comparison metrics between BEFORE and AFTER evidence graphs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    component: str = Field(description="Component name evaluated")
    before_version: str | None = Field(default=None, description="Pre-remediation version")
    after_version: str | None = Field(default=None, description="Post-remediation version")
    before_advisories: list[str] = Field(default_factory=list)
    after_advisories: list[str] = Field(default_factory=list)
    resolved_advisories: list[str] = Field(default_factory=list)
    remaining_advisories: list[str] = Field(default_factory=list)
    before_verdict: Verdict = Field(description="Pre-remediation verdict")
    after_verdict: Verdict = Field(description="Post-remediation verdict")
    vulnerable_symbol_closed: bool = Field(description="Whether vulnerable symbol is severed")
    exposure_path_severed: bool = Field(description="Whether exposure path was severed")
    graph_nodes_before: int = Field(default=0)
    graph_nodes_after: int = Field(default=0)
    graph_edges_before: int = Field(default=0)
    graph_edges_after: int = Field(default=0)
    delta_explanation: str = Field(description="Explanatory text detailing why the verdict changed")


class ProofEvidence(BaseModel):
    """Novelty 1: Proof-Carrying Remediation Bundle.

    Cryptographically and logically complete proof package establishing that a remediation
    candidate provably closed exposure without introducing unverifiable claims.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    proof_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique identifier for this proof artifact",
    )
    finding_id: str = Field(description="Target finding ID being verified")
    candidate_id: str = Field(description="Remediation candidate ID evaluated")
    strategy: str = Field(description="Remediation strategy type applied")
    target_component: str = Field(description="Component name")
    before_snapshot: EvidenceSnapshot = Field(description="Immutable pre-remediation snapshot")
    after_snapshot: EvidenceSnapshot = Field(description="Immutable post-remediation snapshot")
    conditions: ProofConditions = Field(description="Status of the 5 proof conditions")
    comparison: ProofComparison = Field(description="Detailed before/after comparison delta")
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="Evidence IDs associated with proof generation",
    )
    source_locations: list[str] = Field(
        default_factory=list,
        description="Source code locations verified during analysis",
    )
    verification_status: VerificationStatus = Field(
        description="Final verification outcome state"
    )
    uncertainty_reason: str | None = Field(
        default=None,
        description="Reason for uncertainty if status is REQUIRES_VERIFICATION or PARTIALLY_VERIFIED",
    )
    missing_evidence: str | None = Field(
        default=None,
        description="Missing evidence items required to establish full PROVEN_REMEDIATED status",
    )
    final_verdict: Verdict = Field(
        description="Post-remediation verdict determination for the finding"
    )
    executed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of verification execution",
    )


class RemediationVerificationReport(BaseModel):
    """Consolidated report containing all verified remediation candidates across a repository."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    report_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique verification report ID",
    )
    repository_path: str = Field(description="Path to target repository")
    verification_mode: VerificationMode = Field(
        default=VerificationMode.MODE_A_SIMULATED,
        description="Execution mode: MODE_A_SIMULATED or MODE_B_MATERIALIZED",
    )
    total_candidates_verified: int = Field(default=0)
    proven_remediated_count: int = Field(default=0)
    partially_verified_count: int = Field(default=0)
    requires_verification_count: int = Field(default=0)
    failed_count: int = Field(default=0)
    results: list[ProofEvidence] = Field(
        default_factory=list,
        description="Individual proof artifacts for each evaluated candidate",
    )
    summary: str = Field(default="", description="Executive summary of verification results")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Report generation timestamp",
    )
