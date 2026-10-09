"""Snapshot builder for capturing immutable before/after evidence states."""

import json
from pathlib import Path
from typing import Any

from acsa.evidence.graph import EvidenceGraph
from acsa.proof.models import EvidenceSnapshot
from acsa.verdict.vocabulary import Verdict
from acsa.vulnerability.models import Finding


class SnapshotBuilder:
    """Builds immutable, machine-readable EvidenceSnapshots for components and findings."""

    @classmethod
    def capture_snapshot(
        cls,
        phase: str,
        finding: Finding,
        repository_path: Path | str,
        graph: EvidenceGraph | None = None,
        advisories: list[str] | None = None,
        details: dict[str, Any] | None = None,
    ) -> EvidenceSnapshot:
        """Capture an immutable EvidenceSnapshot from a finding and repository state."""
        repo_dir = Path(repository_path)
        comp_name = finding.component.name

        # 1. Read manifest constraint from package.json if present
        manifest_constraint: str | None = None
        pkg_json_path = repo_dir / "package.json"
        if pkg_json_path.exists():
            try:
                pkg_data = json.loads(pkg_json_path.read_text(encoding="utf-8"))
                deps = pkg_data.get("dependencies", {})
                dev_deps = pkg_data.get("devDependencies", {})
                manifest_constraint = deps.get(comp_name) or dev_deps.get(comp_name)
            except Exception:
                manifest_constraint = None

        # 2. Read exact installed version from lockfile if present
        lockfile_version: str | None = None
        lockfile_present = False
        pkg_lock_path = repo_dir / "package-lock.json"
        if pkg_lock_path.exists():
            lockfile_present = True
            try:
                lock_data = json.loads(pkg_lock_path.read_text(encoding="utf-8"))
                # npm v2/v3 packages
                packages = lock_data.get("packages", {})
                pkg_key = f"node_modules/{comp_name}"
                if pkg_key in packages:
                    lockfile_version = packages[pkg_key].get("version")
                elif "" in packages and comp_name in packages[""].get("dependencies", {}):
                    lockfile_version = None
                # npm v1 dependencies
                if not lockfile_version and "dependencies" in lock_data:
                    dep_obj = lock_data["dependencies"].get(comp_name, {})
                    lockfile_version = dep_obj.get("version")
            except Exception:
                lockfile_version = None

        # 3. Extract reachability information
        reach_state = "NOT_REACHABLE" if finding.verdict == Verdict.PROVEN_NOT_AFFECTED else "UNKNOWN"
        entry_points: list[str] = []
        vulnerable_call_sites: list[str] = []
        call_paths: list[list[str]] = []
        source_locations: list[str] = []

        if finding.reachability:
            reach_state = finding.reachability.status.value
            if finding.reachability.entry_point:
                entry_points.append(finding.reachability.entry_point)
            if finding.reachability.call_site:
                vulnerable_call_sites.append(finding.reachability.call_site)
                source_locations.append(finding.reachability.call_site)
            if finding.reachability.evidence_path:
                call_paths.append(list(finding.reachability.evidence_path))

        # 4. Extract context & attacker control information
        attacker_state = "UNKNOWN"
        if finding.context:
            attacker_state = finding.context.status.value
            if finding.context.data_flow_path:
                for step in finding.context.data_flow_path:
                    if hasattr(step, "location") and getattr(step, "location", None):
                        loc = step.location
                        loc_str = f"{loc.file_path}:{loc.line_number}"
                        if loc_str not in source_locations:
                            source_locations.append(loc_str)
                    if hasattr(step, "step_type") and getattr(step, "step_type", None) == "http_entry":
                        expr = getattr(step, "expression", "")
                        if expr and expr not in entry_points:
                            entry_points.append(expr)
                    elif isinstance(step, str) and step.startswith(("GET ", "POST ", "PUT ", "DELETE ", "PATCH ")):
                        if step not in entry_points:
                            entry_points.append(step)

        # 5. Graph digest
        graph_digest = graph.digest() if graph else ""

        # 6. Advisories & applicability
        all_advisories = list(advisories) if advisories else [finding.vulnerability.id]
        applicability_map = {
            finding.vulnerability.id: finding.applicability_status.value
        }

        # 7. Vulnerable symbols
        vuln_symbols = list(finding.vulnerability.vulnerable_symbols)
        if finding.reachability and finding.reachability.target_symbol:
            if finding.reachability.target_symbol not in vuln_symbols:
                vuln_symbols.append(finding.reachability.target_symbol)

        # 8. Dependency relation
        dep_relation = "DIRECT" if manifest_constraint else "TRANSITIVE"

        return EvidenceSnapshot(
            phase=phase,
            repository_identity=str(repo_dir),
            component=comp_name,
            version=finding.component.version or lockfile_version,
            advisories=all_advisories,
            verdict=finding.verdict,
            vulnerability_applicability=applicability_map,
            vulnerable_symbols=vuln_symbols,
            reachability_state=reach_state,
            attacker_control_state=attacker_state,
            entry_points=entry_points,
            vulnerable_call_sites=vulnerable_call_sites,
            call_paths=call_paths,
            evidence_graph_digest=graph_digest,
            evidence_ids=list(finding.evidence_ids),
            source_locations=source_locations,
            dependency_relation=dep_relation,
            manifest_version_constraint=manifest_constraint,
            lockfile_version=lockfile_version,
            lockfile_present=lockfile_present,
            details=details or {},
        )
