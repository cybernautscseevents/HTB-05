"""Domain models for evidence collection, provenance, and graph structures."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field


class EvidenceSource(StrEnum):
    """Provenance sources of evidence collected during analysis."""

    PACKAGE_JSON = "package_json"
    PACKAGE_LOCK = "package_lock"
    CYCLONEDX_SBOM = "cyclonedx_sbom"
    SPDX_SBOM = "spdx_sbom"
    SOURCE_AST = "source_ast"
    IMPORT_GRAPH = "import_graph"
    CALL_GRAPH = "call_graph"
    OSV_ADVISORY = "osv_advisory"
    DYNAMIC_PROBE = "dynamic_probe"
    MANUAL_ASSERTION = "manual_assertion"
    ARTIFACT_INSPECTION = "artifact_inspection"


class Evidence(BaseModel):
    """An individual piece of verifiable evidence."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique evidence ID")
    source: EvidenceSource = Field(description="Originating source of the observation")
    description: str = Field(description="Human-readable explanation of the evidence")
    confidence: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Confidence score for this evidence observation (0.0 - 1.0)",
    )
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp when evidence was observed or generated",
    )
    data: dict[str, Any] = Field(
        default_factory=dict,
        description="Structured raw observation attributes",
    )
    location: str | None = Field(
        default=None,
        description="Optional file location, AST node identifier, or external URL",
    )


class EvidenceNode(BaseModel):
    """A node in the evidence/call/reachability graph."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(description="Unique node identifier")
    node_type: str = Field(
        description="Classification of node (e.g. entry_point, route_handler, app_function, dependency_call, vulnerable_symbol, component)"
    )
    label: str = Field(description="Display label or symbol name")
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional contextual properties (e.g. file, line, method)",
    )


class EvidenceEdge(BaseModel):
    """A directed edge in the evidence/call/reachability graph."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    source: str = Field(description="Source node ID")
    target: str = Field(description="Target node ID")
    relationship: str = Field(
        description="Type of relationship (e.g. imports, calls, depends_on, exposes, reaches)"
    )
    evidence_ids: list[str] = Field(
        default_factory=list,
        description="List of Evidence IDs that support the existence of this edge",
    )
    weight: float = Field(
        default=1.0,
        ge=0.0,
        description="Edge traversal weight or confidence",
    )
    properties: dict[str, Any] = Field(
        default_factory=dict,
        description="Edge metadata",
    )
