"""Remediation orchestration service: simulated patching, verification specs, and report generation."""

import logging
from collections import defaultdict
from pathlib import Path
from uuid import uuid4

from acsa.inventory.models import CanonicalInventory
from acsa.remediation.candidates import CandidateGenerator
from acsa.remediation.dependency_analysis import DependencyAnalyzer
from acsa.remediation.models import (
    CandidateStatus,
    ClosureStatus,
    RemediationAnalysisResult,
    RemediationCandidate,
    RemediationReport,
    RemediationStrategy,
    RemediationVerificationSpec,
)
from acsa.remediation.ranking import RemediationRanker
from acsa.verdict.vocabulary import Verdict
from acsa.vulnerability.models import Finding, Vulnerability, VulnerabilityScanResult

logger = logging.getLogger(__name__)


class RemediationService:
    """Coordinates dependency analysis, candidate generation, minimum-blast-radius ranking, and safe simulation."""

    def __init__(self) -> None:
        pass

    def remediate_finding(
        self,
        repository_path: Path | str,
        finding: Finding,
        inventory: CanonicalInventory,
        all_findings: list[Finding] | None = None,
    ) -> RemediationAnalysisResult:
        """Generate, rank, simulate, and formulate verification spec for a single finding."""
        repo_dir = Path(repository_path) if repository_path else None
        pkg_name = finding.component.name
        curr_ver = finding.component.version

        # 1. Collect all known advisories affecting this package across findings
        all_findings_list = all_findings or [finding]
        package_advisories: list[Vulnerability] = []
        seen_vuln_ids: set[str] = set()

        for f in all_findings_list:
            if f.component.name == pkg_name and f.vulnerability.id not in seen_vuln_ids:
                seen_vuln_ids.add(f.vulnerability.id)
                package_advisories.append(f.vulnerability)

        if not package_advisories:
            package_advisories = [finding.vulnerability]

        # 2. Dependency Graph Analysis
        dep_ctx = DependencyAnalyzer.analyze_component(
            repository_path=repo_dir or Path("."),
            inventory=inventory,
            package_name=pkg_name,
            current_version=curr_ver,
            findings=all_findings_list,
        )

        # 3. Candidate Generation
        raw_candidates = CandidateGenerator.generate_candidates(
            finding=finding,
            dep_ctx=dep_ctx,
            all_package_advisories=package_advisories,
        )

        # 4. Candidate Validation and Invalidation
        validated_candidates: list[RemediationCandidate] = []
        for c in raw_candidates:
            is_valid, validation_msg = CandidateGenerator.validate_candidate(
                candidate=c,
                finding=finding,
                all_package_advisories=package_advisories,
            )
            if not is_valid:
                # Invalidate candidate (Test 7 & 8)
                rejected_cand = c.model_copy(
                    update={
                        "status": CandidateStatus.REJECTED,
                        "reason": f"{c.reason} [REJECTED: {validation_msg}]",
                        "closure_status": ClosureStatus.REQUIRES_VERIFICATION,
                    }
                )
                validated_candidates.append(rejected_cand)
            else:
                validated_candidates.append(c)

        # 5. Attach simulated patch (pure in-memory simulation)
        simulated_candidates: list[RemediationCandidate] = []
        for c in validated_candidates:
            patch_str = self._simulate_patch(repo_dir, c, dep_ctx.declared_constraint)
            sim_cand = c.model_copy(update={"simulated_patch": patch_str})
            simulated_candidates.append(sim_cand)

        # 6. Rank Candidates
        ranked_candidates = RemediationRanker.rank_candidates(
            candidates=simulated_candidates,
            finding=finding,
        )

        # Select top valid candidate if available
        selected: RemediationCandidate | None = None
        for c in ranked_candidates:
            if c.status in (CandidateStatus.ACCEPTED, CandidateStatus.PROPOSED, CandidateStatus.REQUIRES_CONFIRMATION):
                selected = c
                break

        # 7. Generate Blast Radius Explanation
        if selected:
            explanation = RemediationRanker.generate_explanation(
                candidate=selected,
                finding=finding,
                alternatives=ranked_candidates,
            )
        elif ranked_candidates:
            explanation = RemediationRanker.generate_explanation(
                candidate=ranked_candidates[0],
                finding=finding,
            )
        else:
            explanation = "No remediation candidates could be generated."

        # 8. Formulate Post-Remediation Verification Spec
        v_spec: RemediationVerificationSpec | None = None
        if selected and selected.strategy != RemediationStrategy.NO_SAFE_CANDIDATE:
            v_spec = self._build_verification_spec(finding, selected)

        return RemediationAnalysisResult(
            finding_id=finding.id,
            package_name=pkg_name,
            current_version=curr_ver,
            verdict=finding.verdict,
            advisories=[adv.id for adv in package_advisories],
            dependency_relation=dep_ctx.relation,
            parent_package=dep_ctx.parent_package,
            candidates=ranked_candidates,
            selected_candidate=selected,
            verification_spec=v_spec,
            blast_radius_explanation=explanation,
        )

    def remediate_repository(
        self,
        repository_path: Path | str,
        scan_result: VulnerabilityScanResult,
    ) -> RemediationReport:
        """Run end-to-end remediation analysis across all findings in a scanned repository."""
        repo_dir = Path(repository_path)
        results: list[RemediationAnalysisResult] = []

        # Group findings by component name to avoid redundant identical advisory evaluation
        findings_by_comp: dict[str, list[Finding]] = defaultdict(list)
        for f in scan_result.findings:
            findings_by_comp[f.component.name].append(f)

        for finding in scan_result.findings:
            # Skip findings that are PROVEN_NOT_AFFECTED
            if finding.verdict == Verdict.PROVEN_NOT_AFFECTED:
                continue

            comp_findings = findings_by_comp.get(finding.component.name, [finding])
            result = self.remediate_finding(
                repository_path=repo_dir,
                finding=finding,
                inventory=scan_result.inventory,
                all_findings=comp_findings,
            )
            results.append(result)

        remediated_count = sum(1 for r in results if r.selected_candidate is not None)

        return RemediationReport(
            repository_path=str(repo_dir),
            total_findings_evaluated=len(results),
            remediated_findings_count=remediated_count,
            results=results,
        )

    def _simulate_patch(
        self,
        repo_dir: Path | None,
        candidate: RemediationCandidate,
        declared_constraint: str | None,
    ) -> str | None:
        """Generate safe, in-memory unified diff without executing npm or modifying repository files."""
        if candidate.strategy == RemediationStrategy.NO_SAFE_CANDIDATE:
            return None

        pkg = candidate.package_name
        curr_ver = candidate.current_version
        target_ver = candidate.target_version or "latest"

        if candidate.strategy == RemediationStrategy.DIRECT_UPGRADE:
            prefix = "^" if (declared_constraint and declared_constraint.startswith("^")) else ""
            lines = [
                "--- a/package.json",
                "+++ b/package.json",
                f"@@ dependencies for {pkg} @@",
                f'-    "{pkg}": "{declared_constraint or curr_ver}",',
                f'+    "{pkg}": "{prefix}{target_ver}",',
                "",
                "# Lockfile Action: [LOCKFILE_REGENERATION_REQUIRED]",
                "# Run `npm install --package-lock-only` to update package-lock.json safely",
                "# without executing untrusted package lifecycle scripts.",
            ]
            return "\n".join(lines)

        if candidate.strategy == RemediationStrategy.TRANSITIVE_OVERRIDE:
            return "\n".join([
                "--- a/package.json",
                "+++ b/package.json",
                f"@@ npm overrides for {pkg} @@",
                '+  "overrides": {',
                f'+    "{pkg}": "{target_ver}"',
                "+  }",
                "",
                "# Lockfile Action: [LOCKFILE_REGENERATION_REQUIRED]",
                "# Run `npm install --package-lock-only` to recalculate transitive dependency resolution.",
            ])

        if candidate.strategy == RemediationStrategy.PARENT_UPGRADE:
            parent = candidate.dependencies_affected[0] if candidate.dependencies_affected else "parent-pkg"
            return "\n".join([
                "--- a/package.json",
                "+++ b/package.json",
                f"@@ dependencies for {parent} (pulling safe {pkg}@{target_ver}) @@",
                f'-    "{parent}": "<current_parent_version>",',
                f'+    "{parent}": "^{target_ver}",',
                "",
                "# Lockfile Action: [LOCKFILE_REGENERATION_REQUIRED]",
                "# Run `npm install --package-lock-only` to update parent package and transitive dependencies.",
            ])

        if candidate.strategy == RemediationStrategy.REMOVE_DEPENDENCY:
            return "\n".join([
                "--- a/package.json",
                "+++ b/package.json",
                f"@@ remove unused dependency {pkg} @@",
                f'-    "{pkg}": "{declared_constraint or curr_ver}",',
                "",
                "# Lockfile Action: [LOCKFILE_REGENERATION_REQUIRED]",
                "# Run `npm install --package-lock-only` to prune orphaned lockfile entries.",
            ])

        if candidate.strategy == RemediationStrategy.API_REPLACEMENT:
            target_file = candidate.files_changed[0] if candidate.files_changed else "app.js"
            return "\n".join([
                f"--- a/{target_file}",
                f"+++ b/{target_file}",
                "@@ application code replacement @@",
                f"-  // Application call to vulnerable {pkg} symbol",
                "+  // Sanitized or safe replacement call",
            ])

        return None

    def _build_verification_spec(
        self,
        finding: Finding,
        candidate: RemediationCandidate,
    ) -> RemediationVerificationSpec:
        """Formulate post-remediation verification specification (Novelty 1 architecture)."""
        closed_advs = [finding.vulnerability.id, *finding.vulnerability.aliases]

        closed_paths: list[str] = []
        if finding.context and finding.context.data_flow_path:
            closed_paths = finding.context.data_flow_path
        elif finding.reachability and finding.reachability.evidence_path:
            closed_paths = finding.reachability.evidence_path
        else:
            closed_paths = [
                f"{finding.source_artifact_path or 'manifest'} -> {finding.component.name}@{finding.component.version} -> {finding.vulnerability.id}"
            ]

        reqs = [
            "Execute repository test suite to verify 0 regressions",
            "Verify lockfile resolution consistency after dependency update",
            "Confirm complete severance of data flow path to vulnerable symbol",
        ]

        return RemediationVerificationSpec(
            id=str(uuid4()),
            finding_id=finding.id,
            before_verdict=finding.verdict,
            candidate=candidate,
            expected_after_version=candidate.target_version,
            expected_closed_advisories=closed_advs,
            expected_closed_symbols=finding.vulnerability.vulnerable_symbols,
            expected_closed_paths=closed_paths,
            closure_status=candidate.closure_status,
            validation_requirements=reqs,
        )
