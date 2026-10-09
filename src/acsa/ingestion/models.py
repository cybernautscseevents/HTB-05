"""Domain models for code repositories and point-in-time repository snapshots."""

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from acsa.evidence.models import Evidence
from acsa.inventory.models import CanonicalInventory


class Repository(BaseModel):
    """A target source code repository under security analysis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique repository ID")
    name: str = Field(description="Repository name (e.g. org/repo or project name)")
    url: str | None = Field(default=None, description="Repository remote VCS URL if available")
    default_branch: str = Field(default="main", description="Primary default branch")
    ecosystem: str = Field(
        default="npm",
        description="Target package ecosystem (primary target is JavaScript/TypeScript npm)",
    )


class RepositorySnapshot(BaseModel):
    """A point-in-time snapshot of a repository's source and build artifacts."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique snapshot ID")
    repository_id: str = Field(description="Associated repository ID")
    commit_hash: str = Field(description="Git commit SHA or snapshot digest")
    snapshot_path: str = Field(description="Filesystem location of the unpacked snapshot")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Timestamp of snapshot creation",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Arbitrary snapshot metadata (e.g. branch, commit author, build tag)",
    )


class ArtifactType(StrEnum):
    """Supported artifact formats for repository ingestion."""

    PACKAGE_JSON = "package_json"
    PACKAGE_LOCK = "package_lock"
    CYCLONEDX_JSON = "cyclonedx_json"
    SPDX_JSON = "spdx_json"


class DiscoveredArtifact(BaseModel):
    """An artifact file discovered within a target repository workspace."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    path: str = Field(description="Normalized absolute or canonical path to artifact")
    relative_path: str = Field(description="Repository-relative path")
    artifact_type: ArtifactType = Field(description="Detected format classification")
    size_bytes: int = Field(ge=0, description="File size in bytes")
    sha256: str | None = Field(default=None, description="Cryptographic SHA-256 hash of artifact content")


class IngestionWarning(BaseModel):
    """Non-fatal warning encountered during artifact discovery or parsing."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_path: str = Field(description="Associated artifact path")
    message: str = Field(description="Warning description")
    details: dict[str, Any] = Field(default_factory=dict, description="Diagnostic properties")


class IngestionError(BaseModel):
    """Structured error record capturing fatal or recoverable artifact parsing failures."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    artifact_path: str = Field(description="Target artifact path")
    artifact_type: ArtifactType | None = Field(default=None, description="Artifact type if known")
    message: str = Field(description="Error message detailing the failure")
    is_fatal: bool = Field(default=False, description="True if error prevented complete workspace scan")


class IngestionResult(BaseModel):
    """Holistic result of a repository ingestion run containing discoveries, observations, and evidence."""

    model_config = ConfigDict(extra="forbid")

    repository_path: str = Field(description="Target repository root path")
    discovered_artifacts: list[DiscoveredArtifact] = Field(
        default_factory=list, description="Artifacts discovered in workspace"
    )
    inventory: CanonicalInventory = Field(
        description="Canonical inventory populated with multi-source observations"
    )
    evidence: list[Evidence] = Field(
        default_factory=list, description="Evidence objects linking artifacts to observations"
    )
    warnings: list[IngestionWarning] = Field(
        default_factory=list, description="Non-fatal warnings recorded during ingestion"
    )
    errors: list[IngestionError] = Field(
        default_factory=list, description="Errors recorded during discovery or parsing"
    )
    success: bool = Field(
        default=True, description="True if at least one artifact was successfully parsed without fatal error"
    )
    metrics: dict[str, Any] = Field(
        default_factory=dict, description="Summary counts and statistics"
    )
