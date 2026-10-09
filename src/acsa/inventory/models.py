"""Domain models for software components, dependencies, contradictions, and trust assessments."""

from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from acsa.evidence.models import EvidenceSource


class Component(BaseModel):
    """An individual software component identified during inventory analysis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Canonical component ID")
    name: str = Field(description="Normalized component name (e.g. lodash)")
    version: str = Field(description="Exact resolved semantic version (e.g. 4.17.21)")
    purl: str | None = Field(
        default=None,
        description="Standardized Package URL (e.g. pkg:npm/lodash@4.17.21)",
    )
    ecosystem: str = Field(
        default="npm",
        description="Package ecosystem (default: npm)",
    )
    licenses: list[str] = Field(
        default_factory=list,
        description="List of declared or detected licenses (e.g. MIT, Apache-2.0)",
    )
    source_provenance: list[EvidenceSource] = Field(
        default_factory=list,
        description="All sources that observed or confirmed this component",
    )
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional component metadata",
    )


class Dependency(BaseModel):
    """A declared or resolved dependency edge between packages."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(description="Target package name")
    version_constraint: str = Field(
        description="Declared version specifier (e.g. ^4.17.20 or ~1.2.3)"
    )
    resolved_version: str | None = Field(
        default=None,
        description="Resolved concrete version if determined from lockfile or install tree",
    )
    dependency_type: str = Field(
        default="direct",
        description="Classification: direct, dev, peer, optional, or transitive",
    )
    parent_component: str | None = Field(
        default=None,
        description="Name or ID of parent component introducing this dependency",
    )
    scope: str | None = Field(
        default="production",
        description="Runtime scope: production or development",
    )


class InventoryObservation(BaseModel):
    """An individual observation of a component or dependency from a specific artifact source.

    Foundational to Novelty 3 (Contradiction-Aware Inventory): Preserves independent
    observations across manifest, lockfile, and SBOMs without premature reconciliation.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Observation ID")
    component_name: str = Field(description="Normalized name of the observed package")
    version: str | None = Field(
        default=None,
        description="Exact concrete version if observed (e.g. from lockfile or SBOM)",
    )
    version_constraint: str | None = Field(
        default=None,
        description="Declared version range/specifier if observed (e.g. from package.json)",
    )
    dependency_type: str | None = Field(
        default=None,
        description="direct, dev, peer, optional, bundled, or transitive",
    )
    source_type: EvidenceSource = Field(description="EvidenceSource that yielded this observation")
    source_artifact_path: str = Field(
        description="Relative or normalized path of artifact that yielded this observation"
    )
    purl: str | None = Field(
        default=None,
        description="Standardized Package URL if extracted or computed",
    )
    integrity: str | None = Field(
        default=None,
        description="Integrity hash (e.g. sha512-... from lockfile)",
    )
    resolved_url: str | None = Field(
        default=None,
        description="Registry tarball URL if present in lockfile",
    )
    licenses: list[str] = Field(
        default_factory=list,
        description="Licenses reported by the artifact",
    )
    raw_metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Additional parser-extracted raw attributes",
    )


class CanonicalInventory(BaseModel):
    """Multi-source canonical inventory containing all independent observations and resolved models."""

    model_config = ConfigDict(extra="forbid")

    repository_id: str | None = Field(
        default=None, description="Associated repository identifier if applicable"
    )
    observations: list[InventoryObservation] = Field(
        default_factory=list,
        description="Complete list of independent artifact observations",
    )
    components: list[Component] = Field(
        default_factory=list,
        description="Component representations derived from observations",
    )
    dependencies: list[Dependency] = Field(
        default_factory=list,
        description="Dependency relationships extracted from manifests or lockfiles",
    )

    def get_observations_for_component(self, name: str) -> list[InventoryObservation]:
        """Return all independent observations for a given component name."""
        return [obs for obs in self.observations if obs.component_name == name]

    def get_observed_versions(self, name: str) -> set[str]:
        """Return set of distinct concrete versions observed for a component name."""
        return {obs.version for obs in self.observations if obs.component_name == name and obs.version is not None}

    def has_version_discrepancy(self, name: str) -> bool:
        """Check whether multiple distinct concrete versions were observed across sources."""
        return len(self.get_observed_versions(name)) > 1

    @property
    def unique_component_names(self) -> list[str]:
        """Return sorted list of all unique component names observed."""
        return sorted({obs.component_name for obs in self.observations})


class Contradiction(BaseModel):
    """Novelty 3: Discrepancy observed across disparate inventory sources.

    Captures conflicts between manifest, lockfile, SBOM, source AST, and artifact observations.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique contradiction ID")
    component_name: str = Field(description="Name of component subject to conflicting evidence")
    field_name: str = Field(
        description="Specific property with conflicting values (e.g. version, presence, dependencies)"
    )
    conflicting_sources: list[EvidenceSource] = Field(
        description="List of sources presenting incompatible assertions"
    )
    source_values: dict[str, Any] = Field(
        description="Mapping of source name to the specific value observed in that source"
    )
    description: str = Field(description="Human-readable explanation of the contradiction")
    severity: str = Field(
        default="medium",
        description="Impact severity of contradiction: low, medium, or high",
    )
    resolved: bool = Field(
        default=False,
        description="Whether this contradiction was reconciled by downstream evidence",
    )
    resolution_notes: str | None = Field(
        default=None,
        description="Rationale or evidence justifying how contradiction was reconciled",
    )


class TrustAssessment(BaseModel):
    """Trust score and consistency assessment for component inventory credibility."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    id: str = Field(default_factory=lambda: str(uuid4()), description="Unique assessment ID")
    component_name: str = Field(description="Target component evaluated")
    trust_score: float = Field(
        ge=0.0,
        le=1.0,
        description="Confidence/trust score based on cross-source consistency (0.0 to 1.0)",
    )
    evaluated_sources: list[EvidenceSource] = Field(
        description="Sources evaluated during trust assessment"
    )
    has_contradictions: bool = Field(
        default=False,
        description="Indicates whether unresolved contradictions were detected",
    )
    contradiction_ids: list[str] = Field(
        default_factory=list,
        description="Identifiers of contradictions affecting this component",
    )
    confidence_summary: str = Field(
        description="Qualitative summary of component inventory confidence",
    )
