"""Ingestion service coordinating artifact discovery, parsing, and inventory building."""

from pathlib import Path
from typing import Any

from acsa.core.path_security import validate_safe_path
from acsa.evidence.models import Evidence
from acsa.ingestion.discovery import ArtifactDiscovery
from acsa.ingestion.models import (
    ArtifactType,
    IngestionError,
    IngestionResult,
    IngestionWarning,
)
from acsa.ingestion.parsers.base import BaseArtifactParser
from acsa.ingestion.parsers.cyclonedx import CycloneDxParser
from acsa.ingestion.parsers.package_json import PackageJsonParser
from acsa.ingestion.parsers.package_lock import PackageLockParser
from acsa.ingestion.parsers.spdx import SpdxParser
from acsa.inventory.models import CanonicalInventory, Component, Dependency, InventoryObservation


class IngestionService:
    """Orchestrates static discovery and parsing of repository dependency artifacts."""

    def __init__(
        self,
        discovery: ArtifactDiscovery | None = None,
        parsers: dict[ArtifactType, BaseArtifactParser] | None = None,
    ) -> None:
        self.discovery = discovery or ArtifactDiscovery()
        self.parsers: dict[ArtifactType, BaseArtifactParser] = (
            parsers
            if parsers is not None
            else {
                ArtifactType.PACKAGE_JSON: PackageJsonParser(),
                ArtifactType.PACKAGE_LOCK: PackageLockParser(),
                ArtifactType.CYCLONEDX_JSON: CycloneDxParser(),
                ArtifactType.SPDX_JSON: SpdxParser(),
            }
        )

    def ingest_repository(self, repository_path: Path | str) -> IngestionResult:
        """Execute artifact discovery and multi-source parsing for a repository workspace.

        Security: Path is verified against traversal escapes before inspection.
        """
        try:
            repo_root = validate_safe_path(repository_path, repository_path)
            if not repo_root.exists() or not repo_root.is_dir():
                return IngestionResult(
                    repository_path=str(repository_path),
                    discovered_artifacts=[],
                    inventory=CanonicalInventory(observations=[], components=[], dependencies=[]),
                    evidence=[],
                    warnings=[],
                    errors=[
                        IngestionError(
                            artifact_path=str(repository_path),
                            message=f"Repository path does not exist or is not a directory: {repo_root}",
                            is_fatal=True,
                        )
                    ],
                    success=False,
                    metrics={"status": "directory_not_found"},
                )
        except Exception as exc:
            return IngestionResult(
                repository_path=str(repository_path),
                discovered_artifacts=[],
                inventory=CanonicalInventory(observations=[], components=[], dependencies=[]),
                evidence=[],
                warnings=[],
                errors=[
                    IngestionError(
                        artifact_path=str(repository_path),
                        message=f"Invalid repository path: {exc}",
                        is_fatal=True,
                    )
                ],
                success=False,
                metrics={"status": "fatal_path_error"},
            )

        # 1. Discover artifacts
        artifacts, discovery_warnings = self.discovery.discover(repo_root)

        all_observations: list[InventoryObservation] = []
        all_dependencies: list[Dependency] = []
        all_components: list[Component] = []
        all_evidence: list[Evidence] = []
        all_errors: list[IngestionError] = []
        all_warnings: list[IngestionWarning] = list(discovery_warnings)

        parsed_artifacts_count = 0

        # 2. Parse each artifact using appropriate parser
        for artifact in artifacts:
            parser = self.parsers.get(artifact.artifact_type)
            if not parser:
                all_warnings.append(
                    IngestionWarning(
                        artifact_path=artifact.relative_path,
                        message=f"No parser registered for artifact type: {artifact.artifact_type}",
                    )
                )
                continue

            obs, deps, comps, evs, errs, warns = parser.parse(artifact)
            all_observations.extend(obs)
            all_dependencies.extend(deps)
            all_components.extend(comps)
            all_evidence.extend(evs)
            all_errors.extend(errs)
            all_warnings.extend(warns)

            if not errs or len(obs) > 0:
                parsed_artifacts_count += 1

        # 3. Assemble CanonicalInventory preserving all observations
        # Deduplicate components across identical (name, version) while aggregating provenance
        merged_components = self._aggregate_components(all_components)

        inventory = CanonicalInventory(
            repository_id=repo_root.name,
            observations=all_observations,
            components=merged_components,
            dependencies=all_dependencies,
        )

        # 4. Compute metrics
        discrepancy_count = sum(
            1 for name in inventory.unique_component_names if inventory.has_version_discrepancy(name)
        )

        metrics: dict[str, Any] = {
            "artifacts_discovered": len(artifacts),
            "artifacts_parsed": parsed_artifacts_count,
            "total_observations": len(all_observations),
            "unique_components": len(inventory.unique_component_names),
            "components_with_version_discrepancy": discrepancy_count,
            "warning_count": len(all_warnings),
            "error_count": len(all_errors),
        }

        success = len(all_errors) == 0 or parsed_artifacts_count > 0

        return IngestionResult(
            repository_path=str(repo_root),
            discovered_artifacts=artifacts,
            inventory=inventory,
            evidence=all_evidence,
            warnings=all_warnings,
            errors=all_errors,
            success=success,
            metrics=metrics,
        )

    @staticmethod
    def _aggregate_components(components: list[Component]) -> list[Component]:
        """Group components by (name, version) and union their source provenance."""
        grouped: dict[tuple[str, str], Component] = {}
        for comp in components:
            key = (comp.name, comp.version)
            if key not in grouped:
                grouped[key] = comp
            else:
                existing = grouped[key]
                combined_prov = list(set(existing.source_provenance + comp.source_provenance))
                combined_lic = list(set(existing.licenses + comp.licenses))
                grouped[key] = Component(
                    id=existing.id,
                    name=existing.name,
                    version=existing.version,
                    purl=existing.purl or comp.purl,
                    ecosystem=existing.ecosystem,
                    licenses=combined_lic,
                    source_provenance=combined_prov,
                    metadata={**existing.metadata, **comp.metadata},
                )
        return list(grouped.values())
