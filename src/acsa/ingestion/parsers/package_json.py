"""Parser for package.json dependency manifests."""

import json
from pathlib import Path

from acsa.evidence.models import Evidence, EvidenceSource
from acsa.ingestion.models import DiscoveredArtifact, IngestionError, IngestionWarning
from acsa.ingestion.parsers.base import BaseArtifactParser
from acsa.inventory.models import Component, Dependency, InventoryObservation


class PackageJsonParser(BaseArtifactParser):
    """Parses npm package.json manifests and extracts declared dependency requirements."""

    def parse(
        self, artifact: DiscoveredArtifact
    ) -> tuple[
        list[InventoryObservation],
        list[Dependency],
        list[Component],
        list[Evidence],
        list[IngestionError],
        list[IngestionWarning],
    ]:
        observations: list[InventoryObservation] = []
        dependencies: list[Dependency] = []
        components: list[Component] = []
        evidences: list[Evidence] = []
        errors: list[IngestionError] = []
        warnings: list[IngestionWarning] = []

        file_path = Path(artifact.path)
        try:
            with file_path.open("r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError as exc:
            errors.append(
                IngestionError(
                    artifact_path=artifact.relative_path,
                    artifact_type=artifact.artifact_type,
                    message=f"Malformed JSON in package.json: {exc}",
                )
            )
            return observations, dependencies, components, evidences, errors, warnings
        except Exception as exc:
            errors.append(
                IngestionError(
                    artifact_path=artifact.relative_path,
                    artifact_type=artifact.artifact_type,
                    message=f"Could not read package.json: {exc}",
                )
            )
            return observations, dependencies, components, evidences, errors, warnings

        if not isinstance(data, dict):
            errors.append(
                IngestionError(
                    artifact_path=artifact.relative_path,
                    artifact_type=artifact.artifact_type,
                    message="Root package.json structure must be a JSON object",
                )
            )
            return observations, dependencies, components, evidences, errors, warnings

        root_name = data.get("name")
        root_version = data.get("version")

        # Map dependency sections to dependency_type
        sections: list[tuple[str, str, str]] = [
            ("dependencies", "direct", "production"),
            ("devDependencies", "dev", "development"),
            ("optionalDependencies", "optional", "production"),
            ("peerDependencies", "peer", "production"),
        ]

        for section_key, dep_type, scope in sections:
            section_val = data.get(section_key)
            if isinstance(section_val, dict):
                for pkg_name, spec in section_val.items():
                    if not isinstance(pkg_name, str):
                        continue
                    spec_str = str(spec) if spec is not None else "*"

                    obs = InventoryObservation(
                        component_name=pkg_name,
                        version=None,
                        version_constraint=spec_str,
                        dependency_type=dep_type,
                        source_type=EvidenceSource.PACKAGE_JSON,
                        source_artifact_path=artifact.relative_path,
                        purl=f"pkg:npm/{pkg_name}",
                        raw_metadata={"section": section_key, "spec": spec_str},
                    )
                    observations.append(obs)

                    dep = Dependency(
                        name=pkg_name,
                        version_constraint=spec_str,
                        resolved_version=None,
                        dependency_type=dep_type,
                        parent_component=root_name if isinstance(root_name, str) else None,
                        scope=scope,
                    )
                    dependencies.append(dep)
            elif section_val is not None:
                warnings.append(
                    IngestionWarning(
                        artifact_path=artifact.relative_path,
                        message=f"Field '{section_key}' in package.json is not an object",
                    )
                )

        # Handle bundledDependencies / bundleDependencies (can be a list or dict)
        for bundle_key in ("bundledDependencies", "bundleDependencies"):
            bundle_val = data.get(bundle_key)
            if isinstance(bundle_val, list):
                for pkg in bundle_val:
                    if isinstance(pkg, str):
                        obs = InventoryObservation(
                            component_name=pkg,
                            version=None,
                            version_constraint="*",
                            dependency_type="bundled",
                            source_type=EvidenceSource.PACKAGE_JSON,
                            source_artifact_path=artifact.relative_path,
                            purl=f"pkg:npm/{pkg}",
                            raw_metadata={"section": bundle_key},
                        )
                        observations.append(obs)
                        dependencies.append(
                            Dependency(
                                name=pkg,
                                version_constraint="*",
                                resolved_version=None,
                                dependency_type="bundled",
                                parent_component=root_name if isinstance(root_name, str) else None,
                                scope="production",
                            )
                        )
            elif isinstance(bundle_val, dict):
                for pkg, spec in bundle_val.items():
                    if isinstance(pkg, str):
                        obs = InventoryObservation(
                            component_name=pkg,
                            version=None,
                            version_constraint=str(spec),
                            dependency_type="bundled",
                            source_type=EvidenceSource.PACKAGE_JSON,
                            source_artifact_path=artifact.relative_path,
                            purl=f"pkg:npm/{pkg}",
                            raw_metadata={"section": bundle_key, "spec": spec},
                        )
                        observations.append(obs)
                        dependencies.append(
                            Dependency(
                                name=pkg,
                                version_constraint=str(spec),
                                resolved_version=None,
                                dependency_type="bundled",
                                parent_component=root_name if isinstance(root_name, str) else None,
                                scope="production",
                            )
                        )

        evidences.append(
            Evidence(
                source=EvidenceSource.PACKAGE_JSON,
                description=(
                    f"Declared {len(observations)} dependencies in {artifact.relative_path}"
                ),
                location=artifact.relative_path,
                data={
                    "artifact_sha256": artifact.sha256,
                    "root_name": root_name,
                    "root_version": root_version,
                    "dependency_count": len(observations),
                },
            )
        )

        return observations, dependencies, components, evidences, errors, warnings
