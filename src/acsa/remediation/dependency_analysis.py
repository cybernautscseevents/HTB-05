"""Dependency relationship analysis: DIRECT, TRANSITIVE, UNUSED, and parent resolution."""

import json
import logging
from pathlib import Path
from typing import Any, ClassVar

from acsa.evidence.models import EvidenceSource
from acsa.inventory.models import CanonicalInventory
from acsa.reachability.parser import JavaScriptSourceParser
from acsa.remediation.models import DependencyContext, DependencyRelation
from acsa.vulnerability.models import Finding

logger = logging.getLogger(__name__)


class DependencyAnalyzer:
    """Analyzes component position within the repository dependency graph."""

    @classmethod
    def analyze_component(
        cls,
        repository_path: Path | str,
        inventory: CanonicalInventory,
        package_name: str,
        current_version: str,
        findings: list[Finding] | None = None,
    ) -> DependencyContext:
        """Determine whether a package is DIRECT, TRANSITIVE, UNUSED, or UNKNOWN, and identify parents."""
        repo_dir = Path(repository_path) if repository_path else None
        pkg_json_data: dict[str, Any] | None = None
        lock_json_data: dict[str, Any] | None = None

        manifest_file: str | None = None
        lockfile: str | None = None

        if repo_dir and repo_dir.exists():
            pkg_json_path = repo_dir / "package.json"
            if pkg_json_path.exists() and pkg_json_path.is_file():
                try:
                    with pkg_json_path.open("r", encoding="utf-8") as f:
                        pkg_json_data = json.load(f)
                        manifest_file = "package.json"
                except Exception as err:
                    logger.debug("Failed reading package.json: %s", err)

            lock_path = repo_dir / "package-lock.json"
            if lock_path.exists() and lock_path.is_file():
                try:
                    with lock_path.open("r", encoding="utf-8") as f:
                        lock_json_data = json.load(f)
                        lockfile = "package-lock.json"
                except Exception as err:
                    logger.debug("Failed reading package-lock.json: %s", err)

        # 1. Check direct declaration in package.json or inventory
        declared_in_manifest = False
        declared_constraint: str | None = None

        if pkg_json_data:
            dep_sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"]
            for sec in dep_sections:
                sec_dict = pkg_json_data.get(sec)
                if isinstance(sec_dict, dict) and package_name in sec_dict:
                    declared_in_manifest = True
                    declared_constraint = str(sec_dict[package_name])
                    break
        else:
            # Fallback to inventory observations
            for obs in inventory.observations:
                if obs.component_name == package_name and obs.source_type == EvidenceSource.PACKAGE_JSON:
                    declared_in_manifest = True
                    declared_constraint = obs.version_constraint
                    manifest_file = obs.source_artifact_path
                    break

        # 2. Check application code usage (AST / imports)
        is_used_in_code = cls._check_application_usage(repo_dir, package_name, findings)

        # 3. Check contradiction status
        has_contradictions = inventory.has_version_discrepancy(package_name)
        for obs in inventory.observations:
            if obs.component_name == package_name and obs.raw_metadata.get("contradiction"):
                has_contradictions = True
                break

        # 4. Classify relation
        parent_package: str | None = None

        if declared_in_manifest:
            if not is_used_in_code:
                relation = DependencyRelation.UNUSED
            else:
                relation = DependencyRelation.DIRECT
        else:
            # Check if observed in lockfile or SBOM
            in_lock_or_sbom = False
            for obs in inventory.observations:
                if obs.component_name == package_name and obs.source_type in (
                    EvidenceSource.PACKAGE_LOCK,
                    EvidenceSource.CYCLONEDX_SBOM,
                    EvidenceSource.SPDX_SBOM,
                ):
                    in_lock_or_sbom = True
                    break

            if in_lock_or_sbom or lock_json_data:
                relation = DependencyRelation.TRANSITIVE
                parent_package = cls._find_parent_package(pkg_json_data, lock_json_data, package_name)
            else:
                relation = DependencyRelation.UNKNOWN

        return DependencyContext(
            package_name=package_name,
            current_version=current_version,
            relation=relation,
            parent_package=parent_package,
            is_used_in_code=is_used_in_code,
            has_contradictions=has_contradictions,
            manifest_file=manifest_file,
            lockfile=lockfile,
            declared_constraint=declared_constraint,
        )

    _imported_packages_cache: ClassVar[dict[str, set[str]]] = {}

    @classmethod
    def _check_application_usage(
        cls,
        repo_dir: Path | None,
        package_name: str,
        findings: list[Finding] | None,
    ) -> bool:
        """Check if package is imported or required in application source files."""
        # Check findings first if reachability was already evaluated
        if findings:
            for f in findings:
                if f.component.name == package_name and f.reachability:
                    if f.reachability.status.value in ("REACHABLE", "POTENTIALLY_REACHABLE"):
                        return True
                    if f.reachability.target_symbol or f.reachability.call_site:
                        return True

        if not repo_dir or not repo_dir.exists():
            return False

        cache_key = str(repo_dir.resolve())
        if cache_key not in cls._imported_packages_cache:
            imported_set: set[str] = set()
            src_exts = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
            ignore_dirs = {".git", "node_modules", "dist", "build", "coverage", "vendor", ".cache"}

            try:
                parser = JavaScriptSourceParser()
                for path in repo_dir.rglob("*"):
                    if not path.is_file() or path.suffix not in src_exts:
                        continue
                    if any(part in ignore_dirs for part in path.parts):
                        continue

                    try:
                        content = path.read_text(encoding="utf-8", errors="ignore")
                    except Exception:
                        continue

                    parsed = parser.parse_source(str(path), content)
                    for imp in parsed.imports:
                        imported_set.add(imp.module_name)
                        if "/" in imp.module_name:
                            imported_set.add(imp.module_name.split("/")[0])
            except Exception as err:
                logger.debug("Error indexing application imports for %s: %s", repo_dir, err)

            cls._imported_packages_cache[cache_key] = imported_set

        known_imports = cls._imported_packages_cache[cache_key]
        return package_name in known_imports

    @classmethod
    def _find_parent_package(
        cls,
        pkg_json_data: dict[str, Any] | None,
        lock_json_data: dict[str, Any] | None,
        target_pkg: str,
    ) -> str | None:
        """Identify which direct dependency introduced this transitive package."""
        if not lock_json_data:
            return None

        direct_deps: set[str] = set()
        if pkg_json_data:
            for sec in ("dependencies", "devDependencies"):
                d = pkg_json_data.get(sec)
                if isinstance(d, dict):
                    direct_deps.update(d.keys())

        # Check lockfile v2/v3 packages map
        packages = lock_json_data.get("packages")
        if isinstance(packages, dict):
            # 1. Nested path check: "node_modules/parent/node_modules/target_pkg"
            target_suffix = f"/node_modules/{target_pkg}"
            for pkg_path in packages:
                if pkg_path.endswith(target_suffix):
                    # extract immediate parent before /node_modules/{target_pkg}
                    prefix = pkg_path[: -len(target_suffix)]
                    parent_candidate = prefix.replace("\\", "/").split("node_modules/")[-1].strip("/")
                    if parent_candidate:
                        return str(parent_candidate)

            # 2. Check direct dependencies' declared dependencies
            for direct in direct_deps:
                direct_entry = packages.get(f"node_modules/{direct}")
                if isinstance(direct_entry, dict):
                    deps = direct_entry.get("dependencies")
                    if isinstance(deps, dict) and target_pkg in deps:
                        return direct

        # Check lockfile v1 dependencies map
        deps_v1 = lock_json_data.get("dependencies")
        if isinstance(deps_v1, dict):
            for direct in direct_deps:
                entry = deps_v1.get(direct)
                if isinstance(entry, dict):
                    nested = entry.get("dependencies")
                    if isinstance(nested, dict) and target_pkg in nested:
                        return direct
                    requires = entry.get("requires")
                    if isinstance(requires, dict) and target_pkg in requires:
                        return direct

        return None
