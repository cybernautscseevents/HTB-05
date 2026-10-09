"""Domain models for context analysis, input sources, and attacker-controlled data flow."""

from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from acsa.reachability.models import SourceLocation


class AttackerControlStatus(StrEnum):
    """Classification of attacker control over vulnerable code execution paths."""

    CONFIRMED = "CONFIRMED"
    """Verified static evidence demonstrates attacker-controlled input propagates directly or through local flow to the vulnerable symbol."""

    NOT_ESTABLISHED = "NOT_ESTABLISHED"
    """Vulnerable function is reachable, but no external input source or attacker control was established (e.g. called with static constants)."""

    UNKNOWN = "UNKNOWN"
    """Data flow cannot be statically established due to dynamic property access, reflection, or unresolved parameter propagation (UNKNOWN != SAFE)."""


class InputSourceType(StrEnum):
    """Category of external attacker-controlled input source."""

    BODY = "body"
    QUERY = "query"
    PARAMS = "params"
    HEADERS = "headers"
    COOKIES = "cookies"
    URL = "url"
    CUSTOM = "custom"


class InputSource(BaseModel):
    """An identified attacker-controlled input source within an application handler."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source_type: InputSourceType = Field(description="Type of input source (body, query, params, headers, cookies, etc.)")
    expression: str = Field(description="Source expression syntax (e.g. req.body.template, req.query.tpl)")
    location: SourceLocation = Field(description="Source file location where input source is accessed")
    entry_point: str | None = Field(default=None, description="Associated HTTP entry point or route")


class DataFlowStep(BaseModel):
    """An individual hop in a verifiable data flow chain from input source to vulnerable sink."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    step_type: str = Field(description="Hop category: http_entry, input_source, variable_assignment, parameter_passing, sink_call")
    expression: str = Field(description="Code expression or symbol name at this step")
    location: SourceLocation | None = Field(default=None, description="Source location of this hop")
    description: str = Field(description="Human-readable description of this data propagation step")


class ContextAnalysis(BaseModel):
    """Consolidated outcome of Phase 4 context and attacker control evaluation."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: AttackerControlStatus = Field(
        default=AttackerControlStatus.UNKNOWN,
        description="Attacker control classification (CONFIRMED, NOT_ESTABLISHED, UNKNOWN)",
    )
    source: InputSource | None = Field(
        default=None,
        description="Identified attacker-controlled input source if established",
    )
    entry_point: str | None = Field(
        default=None,
        description="HTTP route or application entry point initiating the flow",
    )
    sink: str | None = Field(
        default=None,
        description="Vulnerable function or method invocation receiving the data",
    )
    sink_location: SourceLocation | None = Field(
        default=None,
        description="Source location where vulnerable sink is invoked",
    )
    data_flow_path: list[str] = Field(
        default_factory=list,
        description="Linear step-by-step summary path: [entry -> source -> propagation -> sink]",
    )
    data_flow_steps: list[DataFlowStep] = Field(
        default_factory=list,
        description="Structured provenance records for each data flow hop",
    )
    uncertainty_reason: str | None = Field(
        default=None,
        description="Explanation when attacker control is UNKNOWN or NOT_ESTABLISHED",
    )
    missing_evidence: str | None = Field(
        default=None,
        description="Runtime observation required to resolve uncertainty (supports Dynamic Probing)",
    )
    confidence: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="Confidence score in the context determination",
    )
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="IDs of verifiable Evidence nodes supporting this context result",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context metadata",
    )
