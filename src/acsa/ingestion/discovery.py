"""Artifact discovery layer for repository workspaces."""

import hashlib
import json
from pathlib import Path

from acsa.core.config import get_settings
from acsa.core.path_security import enforce_file_size_limit, validate_safe_path
from acsa.ingestion.models import ArtifactType, DiscoveredArtifact, IngestionWarning

IGNORED_DIRECTORIES = {
    "node_modules",
    ".git",
    ".venv",
    "venv",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".acsa_workspaces",
    "dist",
    "build",
    "__pycache__",
}


class ArtifactDiscovery:
    """Discovers supported dependency manifests, lockfiles, and SBOMs within a workspace."""

    def __init__(self, max_depth: int = 3, max_file_size_bytes: int | None = None) -> None:
        self.max_depth = max_depth
        settings = get_settings()
        self.max_file_size_bytes = (
            max_file_size_bytes if max_file_size_bytes is not None else settings.max_scan_file_size_bytes
        )

    def discover(
        self, base_dir: Path | str
    ) -> tuple[list[DiscoveredArtifact], list[IngestionWarning]]:
        """Safely inspect a repository directory and identify supported artifacts.

        Returns:
            Tuple of (discovered_artifacts, warnings)
        """
        root = validate_safe_path(base_dir, base_dir)
        discovered: list[DiscoveredArtifact] = []
        warnings: list[IngestionWarning] = []

        if not root.is_dir():
            warnings.append(
                IngestionWarning(
                    artifact_path=str(root),
                    message=f"Provided repository path is not a directory: {root}",
                )
            )
            return discovered, warnings

        # Bounded directory walk respecting depth and exclusion boundaries
        for item in self._walk_bounded(root, current_depth=0):
            if not item.is_file():
                continue

            try:
                enforce_file_size_limit(item, self.max_file_size_bytes)
            except Exception as exc:
                warnings.append(
                    IngestionWarning(
                        artifact_path=str(item),
                        message=f"Skipping artifact exceeding size limit: {exc}",
                    )
                )
                continue

            artifact_type = self._detect_artifact_type(item, root)
            if artifact_type is not None:
                try:
                    content = item.read_bytes()
                    sha256 = hashlib.sha256(content).hexdigest()
                    rel_path = str(item.relative_to(root)).replace("\\", "/")
                    discovered.append(
                        DiscoveredArtifact(
                            path=str(item.resolve()),
                            relative_path=rel_path,
                            artifact_type=artifact_type,
                            size_bytes=len(content),
                            sha256=sha256,
                        )
                    )
                except Exception as exc:
                    warnings.append(
                        IngestionWarning(
                            artifact_path=str(item),
                            message=f"Failed to read discovered artifact {item.name}: {exc}",
                        )
                    )

        return discovered, warnings

    def _walk_bounded(self, current_dir: Path, current_depth: int) -> list[Path]:
        """Recursively collect file paths up to max_depth while skipping ignored directories."""
        if current_depth > self.max_depth:
            return []

        files: list[Path] = []
        try:
            for child in current_dir.iterdir():
                if child.is_dir():
                    if child.name not in IGNORED_DIRECTORIES and not child.name.startswith("."):
                        files.extend(self._walk_bounded(child, current_depth + 1))
                elif child.is_file():
                    files.append(child)
        except PermissionError:
            pass
        return files

    def _detect_artifact_type(self, file_path: Path, root: Path) -> ArtifactType | None:
        """Classify file into an ArtifactType based on name and content heuristics."""
        name = file_path.name.lower()

        if name == "package.json":
            return ArtifactType.PACKAGE_JSON

        if name in ("package-lock.json", "npm-shrinkwrap.json"):
            return ArtifactType.PACKAGE_LOCK

        if name.endswith(".json"):
            # Check for CycloneDX or SPDX signatures
            # Quick check if name contains clear hints
            if "cyclonedx" in name or name == "bom.json" or name.endswith(".bom.json"):
                if self._is_cyclonedx_content(file_path):
                    return ArtifactType.CYCLONEDX_JSON

            if "spdx" in name:
                if self._is_spdx_content(file_path):
                    return ArtifactType.SPDX_JSON

            # Content inspection fallback for generic .json files (e.g. sbom.json)
            if self._is_cyclonedx_content(file_path):
                return ArtifactType.CYCLONEDX_JSON
            if self._is_spdx_content(file_path):
                return ArtifactType.SPDX_JSON

        return None

    @staticmethod
    def _is_cyclonedx_content(file_path: Path) -> bool:
        """Inspect beginning of JSON to check for CycloneDX schema signature."""
        try:
            with file_path.open("r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data.get("bomFormat") == "CycloneDX" or "specVersion" in data
        except Exception:
            return False
        return False

    @staticmethod
    def _is_spdx_content(file_path: Path) -> bool:
        """Inspect beginning of JSON to check for SPDX schema signature."""
        try:
            with file_path.open("r", encoding="utf-8", errors="ignore") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    spdx_ver = data.get("spdxVersion")
                    return isinstance(spdx_ver, str) and spdx_ver.startswith("SPDX-")
        except Exception:
            return False
        return False
