"""Domain models for remediation candidates, minimum blast-radius evaluation, and decisions."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

from acsa.verdict.vocabulary import Verdict


class RemediationStrategy(StrEnum):
    """Categorization of remediation approaches."""

    DIRECT_UPGRADE = "DIRECT_UPGRADE"
    """Direct dependency version bump in manifest/lockfile."""

    TRANSITIVE_OVERRIDE = "TRANSITIVE_OVERRIDE"
    """Package manager override/resolution mechanism for transitive dependency."""

    PARENT_UPGRADE = "PARENT_UPGRADE"
    """Upgrading parent direct dependency to pull a safe transitive dependency."""

    API_REPLACEMENT = "API_REPLACEMENT"
    """Replacing vulnerable application-level API/symbol usage with a safe alternative."""

    REMOVE_DEPENDENCY = "REMOVE_DEPENDENCY"
    """Removing an unreferenced, provably unused vulnerable dependency."""

    CONFIG_MITIGATION = "CONFIG_MITIGATION"
    """Configuration boundary or input validation preventing vulnerability trigger."""

    NO_SAFE_CANDIDATE = "NO_SAFE_CANDIDATE"
    """No defensible automated remediation candidate identified."""


class CandidateStatus(StrEnum):
    """Lifecycle status of a remediation candidate."""

    PROPOSED = "PROPOSED"
    """Candidate recommended based on complete, verified evidence."""

    ACCEPTED = "ACCEPTED"
    """Candidate selected as optimal minimum-blast-radius fix."""

    REJECTED = "REJECTED"
    """Candidate rejected (e.g. does not resolve all advisories or fails exposure closure)."""

    REQUIRES_CONFIRMATION = "REQUIRES_CONFIRMATION"
    """Candidate proposed for finding with unverified/unknown aspects; developer review required."""

    CONTRADICTION_BLOCKED = "CONTRADICTION_BLOCKED"
    """Automated fix blocked due to contradictory inventory observations."""

    NO_SAFE_CANDIDATE = "NO_SAFE_CANDIDATE"
    """No candidate satisfies security or compatibility constraints."""


class DependencyRelation(StrEnum):
    """Classification of a component's relationship to the root application."""

    DIRECT = "DIRECT"
    """Declared directly in root manifest (e.g. package.json dependencies/devDependencies)."""

    TRANSITIVE = "TRANSITIVE"
    """Introduced via indirect dependency tree (e.g. package-lock.json or SBOM)."""

    UNUSED = "UNUSED"
    """Declared in manifest but provably unreferenced in source code AST/imports."""

    UNKNOWN = "UNKNOWN"
    """Relation could not be determined or contains conflicting signals."""


class EvidenceConfidence(StrEnum):
    """Transparent evidence classification for remediation candidates."""

    HIGH = "HIGH"
    """Exact installed version, advisory identities, fixed targets, and reachability are verified."""

    MEDIUM = "MEDIUM"
    """Some evidence is indirect, potentially affected, or requires developer confirmation."""

    LOW = "LOW"
    """Critical evidence is uncertain, reachability is UNKNOWN, or signals conflict."""


class ClosureStatus(StrEnum):
    """Explicit status of vulnerability and exposure path closure."""

    PROVEN_CLOSED = "PROVEN_CLOSED"
    """Proven closure of a verified exposure path on an active vulnerable component/symbol."""

    EXPECTED_TO_CLOSE = "EXPECTED_TO_CLOSE"
    """Expected closure for potentially affected or static-only paths requiring dynamic confirmation."""

    REQUIRES_VERIFICATION = "REQUIRES_VERIFICATION"
    """Candidate targets uncertain, unknown, or indirect findings; developer verification required."""


class RemediationCandidate(BaseModel):
    """Structured remediation candidate satisfying Minimum-Blast-Radius criteria."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique identifier for this remediation candidate",
    )
    strategy: RemediationStrategy = Field(
        default=RemediationStrategy.DIRECT_UPGRADE,
        description="Remediation strategy type",
    )
    package_name: str = Field(default="", description="Target component/package name")
    current_version: str = Field(description="Current installed or declared version")
    target_version: str | None = Field(
        default=None,
        description="Proposed safe version or version range if applicable",
    )
    target_component: str | None = Field(
        default=None,
        description="Phase 0 compatibility alias for package_name",
    )
    proposed_version: str | None = Field(
        default=None,
        description="Phase 0 compatibility alias for target_version",
    )
    files_changed: list[str] = Field(
        default_factory=list,
        description="Repository files modified by this candidate",
    )
    dependencies_affected: list[str] = Field(
        default_factory=list,
        description="List of package dependencies added, removed, or changed",
    )
    api_impact: str = Field(
        default="NONE",
        description="Expected API compatibility impact: NONE, MINIMAL, or SIGNIFICANT",
    )
    version_impact: str = Field(
        default="NONE",
        description="Semantic version bump: NONE, PATCH, MINOR, MAJOR, or UNKNOWN",
    )
    closure_status: ClosureStatus = Field(
        default=ClosureStatus.EXPECTED_TO_CLOSE,
        description="Path closure status: PROVEN_CLOSED, EXPECTED_TO_CLOSE, or REQUIRES_VERIFICATION",
    )
    confidence_level: EvidenceConfidence = Field(
        default=EvidenceConfidence.HIGH,
        description="Transparent evidence classification: HIGH, MEDIUM, LOW",
    )
    confidence: str | float | None = Field(
        default=None,
        description="Evidence classification string or legacy float compatibility",
    )
    lockfile_action: str = Field(
        default="NONE",
        description="Lockfile status: NONE, REGENERATION_REQUIRED, or EXACT_CHANGE",
    )
    closed_advisories_count: int = Field(
        default=0,
        description="Number of relevant package advisories resolved by this candidate",
    )
    total_advisories_count: int = Field(
        default=0,
        description="Total relevant package advisories affecting this component",
    )
    closed_paths_count: int = Field(
        default=0,
        description="Number of exposure paths closed by this candidate",
    )
    total_paths_count: int = Field(
        default=0,
        description="Total exposure paths associated with the finding",
    )
    reason: str = Field(
        default="",
        description="Justification and explanation for this candidate",
    )
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="IDs of evidence supporting this candidate",
    )
    preconditions: list[str] = Field(
        default_factory=list,
        description="Preconditions required before applying candidate (e.g. tests pass)",
    )
    expected_effect: str = Field(
        default="",
        description="Expected effect on exposure path and advisories",
    )
    status: CandidateStatus = Field(
        default=CandidateStatus.PROPOSED,
        description="Lifecycle status of candidate",
    )
    simulated_patch: str | None = Field(
        default=None,
        description="Non-destructive in-memory unified diff representation of proposed change",
    )
    blast_radius_score: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
        description="Phase 0 compatibility blast radius score",
    )
    breaking_change_risk: str = Field(
        default="low",
        description="Qualitative risk of breaking backward compatibility: low, medium, high",
    )
    description: str = Field(
        default="",
        description="Summary of the remediation candidate",
    )
    finding_ids: list[str] = Field(
        default_factory=list,
        description="Findings addressed or resolved by this candidate",
    )
    code_changes: list[dict[str, Any]] = Field(
        default_factory=list,
        description="Structured diffs or manifest modifications proposed by candidate",
    )

    strategy_type: str | None = Field(
        default=None,
        description="Phase 0 compatibility strategy type string if provided",
    )

    @model_validator(mode="before")
    @classmethod
    def _normalize_compatibility(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data
        d = dict(data)
        # Phase 0 compatibility mappings
        if "id" in d and "candidate_id" not in d:
            d["candidate_id"] = d.pop("id")
        if d.get("target_component"):
            if not d.get("package_name"):
                d["package_name"] = d["target_component"]
        elif d.get("package_name"):
            d["target_component"] = d["package_name"]

        if d.get("proposed_version"):
            if not d.get("target_version"):
                d["target_version"] = d["proposed_version"]
        elif d.get("target_version"):
            d["proposed_version"] = d["target_version"]

        if "strategy_type" in d:
            raw_st = str(d["strategy_type"]).upper()
            if "strategy" not in d:
                mapping = {
                    "MINIMAL_PATCH": RemediationStrategy.DIRECT_UPGRADE,
                    "MINOR_UPGRADE": RemediationStrategy.DIRECT_UPGRADE,
                    "MAJOR_UPGRADE": RemediationStrategy.DIRECT_UPGRADE,
                    "CALL_SITE_GUARD": RemediationStrategy.API_REPLACEMENT,
                    "DEAD_CODE_ELIMINATION": RemediationStrategy.REMOVE_DEPENDENCY,
                }
                d["strategy"] = mapping.get(raw_st, RemediationStrategy.DIRECT_UPGRADE)
        elif "strategy" in d:
            st_val = d["strategy"]
            d["strategy_type"] = st_val.value.lower() if hasattr(st_val, "value") else str(st_val).lower()
        if "description" in d and not d.get("reason"):
            d["reason"] = d["description"]

        # Confidence normalization
        if "confidence" in d and d["confidence"] is not None:
            raw_c = d["confidence"]
            if isinstance(raw_c, (int, float)):
                if raw_c >= 0.8:
                    d["confidence_level"] = EvidenceConfidence.HIGH
                elif raw_c >= 0.5:
                    d["confidence_level"] = EvidenceConfidence.MEDIUM
                else:
                    d["confidence_level"] = EvidenceConfidence.LOW
                d["confidence"] = d["confidence_level"].value
            elif isinstance(raw_c, str):
                try:
                    d["confidence_level"] = EvidenceConfidence(raw_c.upper())
                    d["confidence"] = d["confidence_level"].value
                except ValueError:
                    pass
        elif "confidence_level" in d:
            c_val = d["confidence_level"]
            d["confidence"] = c_val.value if hasattr(c_val, "value") else str(c_val)
        else:
            d["confidence"] = EvidenceConfidence.HIGH.value

        return d

    @property
    def id(self) -> str:
        """Alias for candidate_id for Phase 0 compatibility."""
        return self.candidate_id

    def get_strategy_type(self) -> str:
        """Return strategy_type if explicitly set, else lower strategy value."""
        return self.strategy_type if self.strategy_type is not None else self.strategy.value.lower()


class RemediationDecision(BaseModel):
    """The authoritative decision selecting the optimal remediation candidate."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Decision ID")
    finding_id: str = Field(description="Target finding being remediated")
    selected_candidate: RemediationCandidate | None = Field(
        default=None,
        description="Chosen candidate fix with the lowest verified blast radius that closes exposure",
    )
    rationale: str = Field(
        description="Technical justification for selecting this remediation over alternatives"
    )
    approved: bool = Field(
        default=False,
        description="Whether this remediation decision has been approved for application",
    )
    decided_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when decision was formulated",
    )


class RemediationVerificationSpec(BaseModel):
    """Pre-verification specification defining expected state after remediation (Novelty 1 foundation)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique specification ID")
    finding_id: str = Field(description="Target finding being verified")
    before_verdict: Verdict = Field(description="Verdict prior to remediation")
    candidate: RemediationCandidate = Field(description="Remediation candidate under verification")
    expected_after_version: str | None = Field(
        default=None,
        description="Expected package version after applying candidate",
    )
    expected_closed_advisories: list[str] = Field(
        default_factory=list,
        description="Advisories expected to be closed/resolved by this remediation",
    )
    expected_closed_symbols: list[str] = Field(
        default_factory=list,
        description="Vulnerable symbols/functions expected to be eliminated from reachability",
    )
    expected_closed_paths: list[str] = Field(
        default_factory=list,
        description="Exposure paths expected to be severed by this candidate",
    )
    closure_status: ClosureStatus = Field(
        default=ClosureStatus.EXPECTED_TO_CLOSE,
        description="Distinction: PROVEN_CLOSED, EXPECTED_TO_CLOSE, or REQUIRES_VERIFICATION",
    )
    validation_requirements: list[str] = Field(
        default_factory=list,
        description="Required validation steps before claiming verified fix (e.g. test suite, build)",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when verification specification was generated",
    )


class DependencyContext(BaseModel):
    """Contextual dependency graph details for a package."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    package_name: str
    current_version: str
    relation: DependencyRelation
    parent_package: str | None = None
    is_used_in_code: bool = False
    has_contradictions: bool = False
    manifest_file: str | None = None
    lockfile: str | None = None
    declared_constraint: str | None = None


class RemediationAnalysisResult(BaseModel):
    """Consolidated remediation outcome for a single finding."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    finding_id: str
    package_name: str
    current_version: str
    verdict: Verdict
    advisories: list[str]
    dependency_relation: DependencyRelation
    parent_package: str | None = None
    candidates: list[RemediationCandidate] = Field(default_factory=list)
    selected_candidate: RemediationCandidate | None = None
    verification_spec: RemediationVerificationSpec | None = None
    blast_radius_explanation: str = ""


class RemediationReport(BaseModel):
    """Complete remediation report for an ingested repository."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    repository_path: str
    total_findings_evaluated: int = 0
    remediated_findings_count: int = 0
    results: list[RemediationAnalysisResult] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
