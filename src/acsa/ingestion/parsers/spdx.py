"""Parser for SPDX JSON Software Bill of Materials (SBOM) documents."""

import json
from pathlib import Path

from acsa.evidence.models import Evidence, EvidenceSource
from acsa.ingestion.models import DiscoveredArtifact, IngestionError, IngestionWarning
from acsa.ingestion.parsers.base import BaseArtifactParser
from acsa.inventory.models import Component, Dependency, InventoryObservation


class SpdxParser(BaseArtifactParser):
    """Parses SPDX JSON SBOMs supporting SPDX 2.2 and 2.3 specifications."""

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
                    message=f"Malformed JSON in SPDX document: {exc}",
                )
            )
            return observations, dependencies, components, evidences, errors, warnings
        except Exception as exc:
            errors.append(
                IngestionError(
                    artifact_path=artifact.relative_path,
                    artifact_type=artifact.artifact_type,
                    message=f"Could not read SPDX document: {exc}",
                )
            )
            return observations, dependencies, components, evidences, errors, warnings

        if not isinstance(data, dict):
            errors.append(
                IngestionError(
                    artifact_path=artifact.relative_path,
                    artifact_type=artifact.artifact_type,
                    message="SPDX root structure must be a JSON object",
                )
            )
            return observations, dependencies, components, evidences, errors, warnings

        spdx_version = data.get("spdxVersion", "unknown")
        raw_packages = data.get("packages", [])

        if not isinstance(raw_packages, list):
            warnings.append(
                IngestionWarning(
                    artifact_path=artifact.relative_path,
                    message="SPDX 'packages' attribute is not an array",
                )
            )
            raw_packages = []

        seen_entries: set[tuple[str, str]] = set()

        for pkg in raw_packages:
            if not isinstance(pkg, dict):
                continue
            name = pkg.get("name")
            if not isinstance(name, str) or not name:
                continue

            version = pkg.get("versionInfo")
            version_str = str(version) if version is not None else ""

            # Extract purl from externalRefs
            purl: str | None = None
            for ref in pkg.get("externalRefs", []):
                if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                    loc = ref.get("referenceLocator")
                    if loc:
                        purl = str(loc)
                        break

            # Extract checksum / integrity
            integrity: str | None = None
            for ck in pkg.get("checksums", []):
                if isinstance(ck, dict) and "algorithm" in ck and "checksumValue" in ck:
                    integrity = f"{ck['algorithm']}:{ck['checksumValue']}"
                    break

            # Extract licenses
            licenses: list[str] = []
            for lic_field in ("licenseDeclared", "licenseConcluded"):
                val = pkg.get(lic_field)
                if val and val not in ("NOASSERTION", "NONE") and isinstance(val, str):
                    licenses.append(val)

            obs = InventoryObservation(
                component_name=name,
                version=version_str if version_str else None,
                version_constraint=None,
                dependency_type="package",
                source_type=EvidenceSource.SPDX_SBOM,
                source_artifact_path=artifact.relative_path,
                purl=purl if purl else (f"pkg:npm/{name}@{version_str}" if version_str else None),
                integrity=integrity,
                licenses=licenses,
                raw_metadata={
                    "spdxVersion": spdx_version,
                    "SPDXID": pkg.get("SPDXID"),
                    "downloadLocation": pkg.get("downloadLocation"),
                },
            )
            observations.append(obs)

            if (name, version_str) not in seen_entries and version_str:
                seen_entries.add((name, version_str))
                components.append(
                    Component(
                        name=name,
                        version=version_str,
                        purl=purl if purl else f"pkg:npm/{name}@{version_str}",
                        ecosystem="npm",
                        licenses=licenses,
                        source_provenance=[EvidenceSource.SPDX_SBOM],
                        metadata={"spdxVersion": spdx_version, "SPDXID": pkg.get("SPDXID")},
                    )
                )

        evidences.append(
            Evidence(
                source=EvidenceSource.SPDX_SBOM,
                description=(
                    f"Reported {len(observations)} packages from SPDX {spdx_version} SBOM ({artifact.relative_path})"
                ),
                location=artifact.relative_path,
                data={
                    "artifact_sha256": artifact.sha256,
                    "spdxVersion": spdx_version,
                    "package_count": len(observations),
                },
            )
        )

        return observations, dependencies, components, evidences, errors, warnings
