"""Parser for CycloneDX JSON Software Bill of Materials (SBOM) documents."""

import json
from pathlib import Path

from acsa.evidence.models import Evidence, EvidenceSource
from acsa.ingestion.models import DiscoveredArtifact, IngestionError, IngestionWarning
from acsa.ingestion.parsers.base import BaseArtifactParser
from acsa.inventory.models import Component, Dependency, InventoryObservation


class CycloneDxParser(BaseArtifactParser):
    """Parses CycloneDX JSON SBOMs targeting the CycloneDX 1.5 specification."""

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
                    message=f"Malformed JSON in CycloneDX document: {exc}",
                )
            )
            return observations, dependencies, components, evidences, errors, warnings
        except Exception as exc:
            errors.append(
                IngestionError(
                    artifact_path=artifact.relative_path,
                    artifact_type=artifact.artifact_type,
                    message=f"Could not read CycloneDX document: {exc}",
                )
            )
            return observations, dependencies, components, evidences, errors, warnings

        if not isinstance(data, dict):
            errors.append(
                IngestionError(
                    artifact_path=artifact.relative_path,
                    artifact_type=artifact.artifact_type,
                    message="CycloneDX root must be a JSON object",
                )
            )
            return observations, dependencies, components, evidences, errors, warnings

        bom_format = data.get("bomFormat", "CycloneDX")
        spec_version = data.get("specVersion", "unknown")
        raw_components = data.get("components", [])

        if not isinstance(raw_components, list):
            warnings.append(
                IngestionWarning(
                    artifact_path=artifact.relative_path,
                    message="CycloneDX 'components' attribute is not an array",
                )
            )
            raw_components = []

        seen_entries: set[tuple[str, str]] = set()

        for comp in raw_components:
            if not isinstance(comp, dict):
                continue
            name = comp.get("name")
            version = comp.get("version")
            if not isinstance(name, str) or not name:
                continue

            version_str = str(version) if version is not None else ""
            purl = comp.get("purl")
            comp_type = comp.get("type", "library")

            # Extract licenses
            licenses: list[str] = []
            for lic_entry in comp.get("licenses", []):
                if isinstance(lic_entry, dict):
                    if "license" in lic_entry and isinstance(lic_entry["license"], dict):
                        lic_id = lic_entry["license"].get("id") or lic_entry["license"].get("name")
                        if lic_id:
                            licenses.append(str(lic_id))
                    elif "expression" in lic_entry:
                        licenses.append(str(lic_entry["expression"]))

            # Extract hashes/integrity
            integrity: str | None = None
            for h in comp.get("hashes", []):
                if isinstance(h, dict) and "alg" in h and "content" in h:
                    integrity = f"{h['alg']}:{h['content']}"
                    break

            obs = InventoryObservation(
                component_name=name,
                version=version_str if version_str else None,
                version_constraint=None,
                dependency_type=str(comp_type),
                source_type=EvidenceSource.CYCLONEDX_SBOM,
                source_artifact_path=artifact.relative_path,
                purl=str(purl) if purl else (f"pkg:npm/{name}@{version_str}" if version_str else None),
                integrity=integrity,
                licenses=licenses,
                raw_metadata={
                    "bomFormat": bom_format,
                    "specVersion": spec_version,
                    "type": comp_type,
                    "bom-ref": comp.get("bom-ref"),
                },
            )
            observations.append(obs)

            if (name, version_str) not in seen_entries and version_str:
                seen_entries.add((name, version_str))
                components.append(
                    Component(
                        name=name,
                        version=version_str,
                        purl=str(purl) if purl else f"pkg:npm/{name}@{version_str}",
                        ecosystem="npm",
                        licenses=licenses,
                        source_provenance=[EvidenceSource.CYCLONEDX_SBOM],
                        metadata={"bomFormat": bom_format, "specVersion": spec_version},
                    )
                )

        evidences.append(
            Evidence(
                source=EvidenceSource.CYCLONEDX_SBOM,
                description=(
                    f"Reported {len(observations)} components from CycloneDX {spec_version} SBOM ({artifact.relative_path})"
                ),
                location=artifact.relative_path,
                data={
                    "artifact_sha256": artifact.sha256,
                    "bomFormat": bom_format,
                    "specVersion": spec_version,
                    "component_count": len(observations),
                },
            )
        )

        return observations, dependencies, components, evidences, errors, warnings
