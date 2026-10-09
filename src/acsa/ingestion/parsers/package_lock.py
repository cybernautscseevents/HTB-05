"""Parser for npm package-lock.json files supporting lockfileVersion 1, 2, and 3."""

import json
from pathlib import Path
from typing import Any

from acsa.evidence.models import Evidence, EvidenceSource
from acsa.ingestion.models import DiscoveredArtifact, IngestionError, IngestionWarning
from acsa.ingestion.parsers.base import BaseArtifactParser
from acsa.inventory.models import Component, Dependency, InventoryObservation


class PackageLockParser(BaseArtifactParser):
    """Parses npm package-lock.json and npm-shrinkwrap.json files."""

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
                    message=f"Malformed JSON in package-lock.json: {exc}",
                )
            )
            return observations, dependencies, components, evidences, errors, warnings
        except Exception as exc:
            errors.append(
                IngestionError(
                    artifact_path=artifact.relative_path,
                    artifact_type=artifact.artifact_type,
                    message=f"Could not read package-lock.json: {exc}",
                )
            )
            return observations, dependencies, components, evidences, errors, warnings

        if not isinstance(data, dict):
            errors.append(
                IngestionError(
                    artifact_path=artifact.relative_path,
                    artifact_type=artifact.artifact_type,
                    message="Root package-lock.json structure must be a JSON object",
                )
            )
            return observations, dependencies, components, evidences, errors, warnings

        lockfile_version = data.get("lockfileVersion")
        if lockfile_version not in (1, 2, 3):
            warnings.append(
                IngestionWarning(
                    artifact_path=artifact.relative_path,
                    message=f"Unrecognized or unsupported lockfileVersion: {lockfile_version}",
                    details={"lockfileVersion": lockfile_version},
                )
            )

        # Track seen (name, version) pairs from lockfile to avoid duplicate components
        seen_entries: set[tuple[str, str]] = set()

        packages_dict = data.get("packages")
        if isinstance(packages_dict, dict) and packages_dict:
            # Parse v2 / v3 format with "packages" key
            for pkg_path, pkg_info in packages_dict.items():
                if not isinstance(pkg_info, dict) or not pkg_path:
                    continue  # skip root package ("") or invalid entries

                pkg_name = self._extract_package_name_from_path(pkg_path)
                if not pkg_name:
                    continue

                version = pkg_info.get("version")
                if not isinstance(version, str):
                    continue

                resolved = pkg_info.get("resolved")
                integrity = pkg_info.get("integrity")
                is_dev = bool(pkg_info.get("dev", False))
                is_optional = bool(pkg_info.get("optional", False))
                dep_type = "dev" if is_dev else ("optional" if is_optional else "direct")

                purl = f"pkg:npm/{pkg_name}@{version}"

                obs = InventoryObservation(
                    component_name=pkg_name,
                    version=version,
                    version_constraint=None,
                    dependency_type=dep_type,
                    source_type=EvidenceSource.PACKAGE_LOCK,
                    source_artifact_path=artifact.relative_path,
                    purl=purl,
                    integrity=str(integrity) if integrity else None,
                    resolved_url=str(resolved) if resolved else None,
                    raw_metadata={
                        "lockfileVersion": lockfile_version,
                        "package_path": pkg_path,
                        "dev": is_dev,
                        "optional": is_optional,
                    },
                )
                observations.append(obs)

                if (pkg_name, version) not in seen_entries:
                    seen_entries.add((pkg_name, version))
                    components.append(
                        Component(
                            name=pkg_name,
                            version=version,
                            purl=purl,
                            ecosystem="npm",
                            source_provenance=[EvidenceSource.PACKAGE_LOCK],
                            metadata={
                                "resolved": resolved,
                                "integrity": integrity,
                                "lockfileVersion": lockfile_version,
                            },
                        )
                    )
        else:
            # Fallback to v1 format with recursive "dependencies" key
            deps_dict = data.get("dependencies")
            if isinstance(deps_dict, dict):
                self._parse_v1_dependencies(
                    deps_dict,
                    artifact.relative_path,
                    lockfile_version,
                    observations,
                    components,
                    seen_entries,
                )

        evidences.append(
            Evidence(
                source=EvidenceSource.PACKAGE_LOCK,
                description=(
                    f"Resolved {len(observations)} installed component instances from {artifact.relative_path} (lockfile v{lockfile_version})"
                ),
                location=artifact.relative_path,
                data={
                    "artifact_sha256": artifact.sha256,
                    "lockfileVersion": lockfile_version,
                    "resolved_package_count": len(observations),
                },
            )
        )

        return observations, dependencies, components, evidences, errors, warnings

    def _parse_v1_dependencies(
        self,
        deps_dict: dict[str, Any],
        artifact_path: str,
        lockfile_version: Any,
        observations: list[InventoryObservation],
        components: list[Component],
        seen_entries: set[tuple[str, str]],
    ) -> None:
        """Recursively extract resolved dependencies from v1 lockfile format."""
        for pkg_name, pkg_info in deps_dict.items():
            if not isinstance(pkg_info, dict):
                continue
            version = pkg_info.get("version")
            if not isinstance(version, str):
                continue

            resolved = pkg_info.get("resolved")
            integrity = pkg_info.get("integrity")
            is_dev = bool(pkg_info.get("dev", False))
            is_optional = bool(pkg_info.get("optional", False))
            dep_type = "dev" if is_dev else ("optional" if is_optional else "direct")

            purl = f"pkg:npm/{pkg_name}@{version}"

            obs = InventoryObservation(
                component_name=pkg_name,
                version=version,
                version_constraint=None,
                dependency_type=dep_type,
                source_type=EvidenceSource.PACKAGE_LOCK,
                source_artifact_path=artifact_path,
                purl=purl,
                integrity=str(integrity) if integrity else None,
                resolved_url=str(resolved) if resolved else None,
                raw_metadata={
                    "lockfileVersion": lockfile_version,
                    "dev": is_dev,
                    "optional": is_optional,
                },
            )
            observations.append(obs)

            if (pkg_name, version) not in seen_entries:
                seen_entries.add((pkg_name, version))
                components.append(
                    Component(
                        name=pkg_name,
                        version=version,
                        purl=purl,
                        ecosystem="npm",
                        source_provenance=[EvidenceSource.PACKAGE_LOCK],
                        metadata={"resolved": resolved, "integrity": integrity},
                    )
                )

            nested_deps = pkg_info.get("dependencies")
            if isinstance(nested_deps, dict):
                self._parse_v1_dependencies(
                    nested_deps,
                    artifact_path,
                    lockfile_version,
                    observations,
                    components,
                    seen_entries,
                )

    @staticmethod
    def _extract_package_name_from_path(pkg_path: str) -> str | None:
        """Extract the npm package name from node_modules path.

        Handles scoped packages (e.g. node_modules/@scope/pkg) and nested paths.
        """
        parts = pkg_path.replace("\\", "/").split("node_modules/")
        if len(parts) < 2:
            return None
        last_segment = parts[-1].strip("/")
        if not last_segment:
            return None
        return last_segment
