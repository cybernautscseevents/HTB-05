"""Domain models for Uncertainty-Guided Dynamic Probe Planning."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from acsa.verdict.vocabulary import Verdict


class ProbeType(StrEnum):
    """Categorical classification of targeted dynamic probes."""

    HTTP_INPUT_TO_SINK = "HTTP_INPUT_TO_SINK"
    """Observe whether attacker-controlled HTTP request data propagates to a vulnerable sink."""

    MODULE_RESOLUTION = "MODULE_RESOLUTION"
    """Observe runtime module resolution when dynamic import/require prevents static determination."""

    SYMBOL_INVOCATION = "SYMBOL_INVOCATION"
    """Observe whether a vulnerable symbol is actually invoked during application operations."""

    ROUTE_EXECUTION = "ROUTE_EXECUTION"
    """Observe whether dynamic framework routing dispatches to the candidate handler."""

    DEPENDENCY_VERSION_CONFIRMATION = "DEPENDENCY_VERSION_CONFIRMATION"
    """Observe the exact resolved package version when manifest/lockfile evidence is incomplete."""


class ProbeEvaluationStatus(StrEnum):
    """Status outcome of evaluating an external observation against a probe specification."""

    PENDING = "PENDING"
    """Probe specification generated; awaiting empirical observation."""

    CONFIRMED = "CONFIRMED"
    """Observation empirically verified the required condition."""

    NOT_CONFIRMED = "NOT_CONFIRMED"
    """Observation empirically verified the absence or failure of the required condition."""

    INCONCLUSIVE = "INCONCLUSIVE"
    """Supplied observation data was incomplete or ambiguous; uncertainty remains unresolved."""


class SafetyConstraint(StrEnum):
    """Standard defensive safety constraints enforced on probe execution."""

    NO_UNTRUSTED_SCRIPTS = "Do not execute repository npm lifecycle scripts or arbitrary code."
    NON_DESTRUCTIVE_PAYLOAD = "Use benign probe marker strings; never send destructive or exploit payloads."
    ISOLATED_SANDBOX = "Observe in an isolated sandbox or pre-configured test environment only."
    READ_ONLY_ACCESS = "Maintain read-only filesystem access; do not modify application state."
    EXPLICIT_EXECUTION_ONLY = "Never execute probes automatically without analyst authorization."


class ProbeSpecification(BaseModel):
    """Machine-readable, actionable specification for a targeted dynamic probe."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    probe_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique probe specification identifier",
    )
    finding_id: str = Field(description="Associated ACSA finding identifier")
    probe_type: ProbeType = Field(description="Categorical type of probe")
    target_component: str = Field(description="Target dependency or package name")
    target_symbol: str | None = Field(
        default=None,
        description="Target vulnerable function, method, or API symbol",
    )
    entry_point: str | None = Field(
        default=None,
        description="Application HTTP entry point or route handler (e.g. POST /render)",
    )
    input_source: str | None = Field(
        default=None,
        description="Attacker-controlled input source expression (e.g. req.body.template)",
    )
    uncertainty_reason: str = Field(
        description="Why static analysis could not reach a definitive verdict",
    )
    missing_evidence: str = Field(
        description="Specific observation or evidence artifact required to resolve uncertainty",
    )
    required_observation: str = Field(
        description="Concrete runtime behavior that must be observed",
    )
    success_condition: str = Field(
        description="Observation criteria confirming the vulnerable condition or exposure",
    )
    failure_condition: str = Field(
        description="Observation criteria refuting the vulnerable condition or exposure",
    )
    safety_constraints: list[str] = Field(
        default_factory=lambda: [
            SafetyConstraint.NO_UNTRUSTED_SCRIPTS.value,
            SafetyConstraint.NON_DESTRUCTIVE_PAYLOAD.value,
            SafetyConstraint.ISOLATED_SANDBOX.value,
            SafetyConstraint.READ_ONLY_ACCESS.value,
            SafetyConstraint.EXPLICIT_EXECUTION_ONLY.value,
        ],
        description="Explicit safety boundaries governing probe execution",
    )
    expected_verdict_if_confirmed: Verdict = Field(
        description="Authoritative ACSA verdict if the probe observation confirms the condition",
    )
    expected_verdict_if_not_confirmed: Verdict = Field(
        description="Authoritative ACSA verdict if the probe observation refutes the condition",
    )
    priority_rank: int = Field(
        default=1,
        description="Deterministic priority ranking (1 = highest priority)",
    )
    status: ProbeEvaluationStatus = Field(
        default=ProbeEvaluationStatus.PENDING,
        description="Evaluation state of the probe",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when probe specification was generated",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Supplemental contextual metadata",
    )


class ProbeObservation(BaseModel):
    """Structured empirical observation provided by an analyst or instrumented test runner."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    probe_id: str = Field(description="Identifier of the ProbeSpecification being validated")
    finding_id: str = Field(description="Identifier of the associated ACSA finding")
    observed: bool | None = Field(
        description="True if condition observed; False if refuted; None if inconclusive",
    )
    evidence_payload: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured runtime trace, invocation logs, or resolved metadata",
    )
    observed_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when observation was captured",
    )
    observer_notes: str | None = Field(
        default=None,
        description="Analyst commentary or execution environment notes",
    )


class ProbeEvaluation(BaseModel):
    """Authoritative outcome of evaluating an observation against a probe specification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    evaluation_id: str = Field(
        default_factory=lambda: str(uuid4()),
        description="Unique evaluation identifier",
    )
    probe_id: str = Field(description="Target probe specification identifier")
    finding_id: str = Field(description="Target finding identifier")
    evaluation_status: ProbeEvaluationStatus = Field(
        description="Outcome status (CONFIRMED, NOT_CONFIRMED, INCONCLUSIVE)",
    )
    original_verdict: Verdict = Field(
        description="Finding verdict prior to dynamic probe evaluation",
    )
    resolved_verdict: Verdict = Field(
        description="Updated ACSA verdict resulting from empirical probe evaluation",
    )
    rationale: str = Field(
        description="Explainable rationale connecting observation evidence to verdict transition",
    )
    updated_evidence_ids: list[str] = Field(
        default_factory=list,
        description="IDs of newly generated evidence objects",
    )
    evaluated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of evaluation",
    )


class ProbePlanReport(BaseModel):
    """Consolidated report of dynamic probe planning across an analyzed repository."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    repository_path: str = Field(description="Root path of repository analyzed")
    total_unknown_findings: int = Field(description="Count of findings with UNKNOWN verdicts")
    total_probes_generated: int = Field(description="Count of probe specifications generated")
    probes_by_type: dict[str, int] = Field(
        default_factory=dict,
        description="Breakdown of probes by categorical ProbeType",
    )
    probes: list[ProbeSpecification] = Field(
        default_factory=list,
        description="Prioritized list of probe specifications",
    )
    summary: str = Field(description="High-level analyst summary")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of plan generation",
    )
