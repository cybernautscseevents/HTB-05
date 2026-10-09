"""Proof verification service orchestrating isolated workspaces, re-analysis, and evidence generation."""

import json
import logging
import shutil
import tempfile
from pathlib import Path
from uuid import uuid4

from acsa.context.service import ContextService
from acsa.evidence.graph import EvidenceGraph
from acsa.ingestion.service import IngestionService
from acsa.proof.comparison import ProofComparisonEngine
from acsa.proof.models import (
    ProofEvidence,
    RemediationVerificationReport,
    TestValidationStatus,
    VerificationMode,
)
from acsa.proof.snapshot import SnapshotBuilder
from acsa.proof.verifier import ProofVerifier
from acsa.reachability.service import ReachabilityService
from acsa.remediation.models import (
    CandidateStatus,
    RemediationCandidate,
    RemediationStrategy,
)
from acsa.remediation.service import RemediationService
from acsa.verdict.service import EvidenceFusionService
from acsa.verdict.vocabulary import Verdict
from acsa.vulnerability.models import ApplicabilityStatus, Finding, VulnerabilityScanResult
from acsa.vulnerability.service import VulnerabilityService

logger = logging.getLogger(__name__)


class RemediationProofService:
    """Coordinates end-to-end Proof-Carrying Remediation validation across isolated workspaces."""

    @classmethod
    def run_full_analysis(
        cls,
        repository_path: Path | str,
    ) -> tuple[VulnerabilityScanResult, EvidenceGraph]:
        """Execute the complete Phase 1-4 pipeline against a repository workspace."""
        repo_dir = Path(repository_path)

        # 1. Ingestion
        ingest_service = IngestionService()
        ingest_result = ingest_service.ingest_repository(repo_dir)

        # 2. OSV Intelligence
        vuln_service = VulnerabilityService()
        scan_result = vuln_service.scan_inventory(
            ingest_result.inventory, repository_path=str(repo_dir)
        )

        # 3. Static Reachability
        reach_service = ReachabilityService()
        findings_reach, reach_ev, graph = reach_service.analyze_findings(
            repo_dir, scan_result.findings
        )

        # 4. Context & Attacker-Controlled Flow
        ctx_service = ContextService()
        findings_ctx, ctx_ev = ctx_service.analyze_findings(
            repo_dir, findings_reach, graph=graph
        )

        intermediate_result = scan_result.model_copy(
            update={
                "findings": findings_ctx,
                "evidence": list(scan_result.evidence) + reach_ev + ctx_ev,
                "reachability_evaluated": True,
                "context_evaluated": True,
            }
        )

        # 5. Evidence Fusion & Verdict
        fusion_service = EvidenceFusionService()
        final_result = fusion_service.enrich_scan_result(intermediate_result, graph=graph)

        return final_result, graph

    @classmethod
    def apply_candidate_in_workspace(
        cls,
        candidate: RemediationCandidate,
        workspace_path: Path,
        mode: VerificationMode,
    ) -> bool:
        """Apply candidate modifications strictly within the isolated workspace.

        Returns:
            lockfile_not_regenerated (bool): True if lockfile changes were required but not safely materialized.
        """
        pkg_name = candidate.package_name
        target_ver = candidate.target_version
        lockfile_not_regenerated = False

        pkg_json_path = workspace_path / "package.json"
        pkg_lock_path = workspace_path / "package-lock.json"

        # Handle Manifest changes
        if pkg_json_path.exists():
            try:
                pkg_data = json.loads(pkg_json_path.read_text(encoding="utf-8"))

                if candidate.strategy == RemediationStrategy.REMOVE_DEPENDENCY:
                    if "dependencies" in pkg_data and pkg_name in pkg_data["dependencies"]:
                        del pkg_data["dependencies"][pkg_name]
                    if "devDependencies" in pkg_data and pkg_name in pkg_data["devDependencies"]:
                        del pkg_data["devDependencies"][pkg_name]
                elif candidate.strategy == RemediationStrategy.TRANSITIVE_OVERRIDE:
                    if target_ver:
                        overrides = pkg_data.setdefault("overrides", {})
                        overrides[pkg_name] = target_ver
                elif target_ver:
                    # DIRECT_UPGRADE or PARENT_UPGRADE
                    new_constraint = f"^{target_ver}" if not target_ver.startswith(("^", "~")) else target_ver
                    if "dependencies" in pkg_data and pkg_name in pkg_data["dependencies"]:
                        pkg_data["dependencies"][pkg_name] = new_constraint
                    elif "devDependencies" in pkg_data and pkg_name in pkg_data["devDependencies"]:
                        pkg_data["devDependencies"][pkg_name] = new_constraint

                pkg_json_path.write_text(json.dumps(pkg_data, indent=2), encoding="utf-8")
            except Exception as err:
                logger.warning("Failed to apply candidate to package.json in workspace: %s", err)

        # Handle Lockfile behavior
        if pkg_lock_path.exists():
            if mode == VerificationMode.MODE_B_MATERIALIZED:
                # Mode B: Safely materialize post-remediation version in lockfile without running npm
                try:
                    lock_data = json.loads(pkg_lock_path.read_text(encoding="utf-8"))
                    packages = lock_data.get("packages", {})
                    pkg_key = f"node_modules/{pkg_name}"

                    if candidate.strategy == RemediationStrategy.REMOVE_DEPENDENCY:
                        packages.pop(pkg_key, None)
                        if "dependencies" in lock_data:
                            lock_data["dependencies"].pop(pkg_name, None)
                    elif target_ver:
                        clean_ver = target_ver.lstrip("^~>=")
                        if pkg_key in packages:
                            packages[pkg_key]["version"] = clean_ver
                        if "dependencies" in lock_data and pkg_name in lock_data["dependencies"]:
                            lock_data["dependencies"][pkg_name]["version"] = clean_ver

                    pkg_lock_path.write_text(json.dumps(lock_data, indent=2), encoding="utf-8")
                except Exception as err:
                    logger.warning("Failed to materialize lockfile in Mode B: %s", err)
            else:
                # Mode A: Lockfile is NOT regenerated to avoid running npm install
                lockfile_not_regenerated = True

        # Handle API replacement (source file patching)
        if candidate.strategy == RemediationStrategy.API_REPLACEMENT:
            for file_name in candidate.files_changed:
                if not file_name.endswith(".json"):
                    src_file = workspace_path / file_name
                    if src_file.exists():
                        try:
                            content = src_file.read_text(encoding="utf-8")
                            # Replace vulnerable symbol call if documented
                            if "template(" in content:
                                content = content.replace("template(", "escape(")
                            src_file.write_text(content, encoding="utf-8")
                        except Exception as err:
                            logger.warning("Failed to patch source file %s: %s", file_name, err)

        return lockfile_not_regenerated

    @classmethod
    def verify_candidate(
        cls,
        repository_path: Path | str,
        finding: Finding,
        candidate: RemediationCandidate,
        mode: VerificationMode = VerificationMode.MODE_A_SIMULATED,
        before_graph: EvidenceGraph | None = None,
        test_status: TestValidationStatus = TestValidationStatus.NOT_EXECUTED,
        test_reason: str | None = "Repository command execution disabled by security policy.",
    ) -> ProofEvidence:
        """Verify a remediation candidate by creating an isolated workspace, applying changes, and re-analyzing."""
        repo_dir = Path(repository_path)

        # 1. Capture BEFORE snapshot
        before_snap = SnapshotBuilder.capture_snapshot(
            phase="before",
            finding=finding,
            repository_path=repo_dir,
            graph=before_graph,
            advisories=[finding.vulnerability.id],
        )

        # 2. Setup isolated temporary workspace
        with tempfile.TemporaryDirectory(prefix="acsa_proof_ws_") as temp_dir:
            ws_path = Path(temp_dir)

            # Copy repository safely (excluding git and caches)
            shutil.copytree(
                repo_dir,
                ws_path,
                dirs_exist_ok=True,
                ignore=shutil.ignore_patterns(".git", "*.pyc", "__pycache__"),
            )

            # 3. Apply candidate inside isolated workspace
            lockfile_not_regenerated = cls.apply_candidate_in_workspace(
                candidate=candidate,
                workspace_path=ws_path,
                mode=mode,
            )

            # 4. Re-run complete ACSA analysis against AFTER workspace
            after_scan_result, after_graph = cls.run_full_analysis(ws_path)

            # 5. Identify corresponding AFTER finding for this component
            matching_after = [
                f for f in after_scan_result.findings
                if f.component.name == finding.component.name
            ]

            if matching_after:
                # Find finding matching this advisory if possible, else take first
                adv_matching = [f for f in matching_after if f.vulnerability.id == finding.vulnerability.id]
                after_finding = adv_matching[0] if adv_matching else matching_after[0]
            else:
                # Component is either no longer vulnerable (0 advisories returned) or removed
                # Synthesize a safe post-remediation observation
                after_comp = finding.component.model_copy(
                    update={"version": candidate.target_version or finding.component.version}
                )
                after_finding = Finding(
                    vulnerability=finding.vulnerability,
                    component=after_comp,
                    verdict=Verdict.PROVEN_NOT_AFFECTED,
                    applicability_status=ApplicabilityStatus.NOT_AFFECTED,
                    source_artifact_path=finding.source_artifact_path,
                    evidence_ids=[],
                    confidence=1.0,
                    notes="No active vulnerabilities identified in post-remediation analysis.",
                )

            # 6. Capture AFTER snapshot
            after_snap = SnapshotBuilder.capture_snapshot(
                phase="after",
                finding=after_finding,
                repository_path=ws_path,
                graph=after_graph,
                advisories=[finding.vulnerability.id] if after_finding.verdict != Verdict.PROVEN_NOT_AFFECTED else [],
            )

            # 7. Compute before/after delta comparison
            comparison = ProofComparisonEngine.compare(
                before=before_snap,
                after=after_snap,
                before_graph=before_graph,
                after_graph=after_graph,
            )

            # 8. Evaluate machine-verifiable proof conditions
            conditions, status, uncertainty_reason, missing_evidence = ProofVerifier.evaluate(
                before=before_snap,
                after=after_snap,
                comparison=comparison,
                lockfile_not_regenerated=lockfile_not_regenerated,
                test_status=test_status,
                test_reason=test_reason,
            )

            # Collect source locations
            all_locs = list(set(before_snap.source_locations + after_snap.source_locations))

            # Assemble ProofEvidence
            return ProofEvidence(
                proof_id=str(uuid4()),
                finding_id=finding.id,
                candidate_id=candidate.candidate_id,
                strategy=candidate.strategy.value,
                target_component=finding.component.name,
                before_snapshot=before_snap,
                after_snapshot=after_snap,
                conditions=conditions,
                comparison=comparison,
                evidence_ids=before_snap.evidence_ids + after_snap.evidence_ids,
                source_locations=all_locs,
                verification_status=status,
                uncertainty_reason=uncertainty_reason,
                missing_evidence=missing_evidence,
                final_verdict=after_snap.verdict,
            )

    @classmethod
    def verify_repository(
        cls,
        repository_path: Path | str,
        scan_result: VulnerabilityScanResult | None = None,
        graph: EvidenceGraph | None = None,
        mode: VerificationMode = VerificationMode.MODE_A_SIMULATED,
        candidate_id: str | None = None,
        test_status: TestValidationStatus = TestValidationStatus.NOT_EXECUTED,
    ) -> RemediationVerificationReport:
        """Run verification across remediation candidates generated for a repository."""
        repo_dir = Path(repository_path)

        # 1. Run full analysis if not provided
        if scan_result is None or graph is None:
            scan_result, graph = cls.run_full_analysis(repo_dir)

        # 2. Generate remediation candidates
        rem_service = RemediationService()
        rem_report = rem_service.remediate_repository(repo_dir, scan_result)

        proof_results: list[ProofEvidence] = []
        proven_count = 0
        partially_count = 0
        requires_count = 0
        failed_count = 0

        # Map findings by ID for lookup
        finding_map = {f.id: f for f in scan_result.findings}

        for rem_res in rem_report.results:
            cand = None
            if candidate_id:
                if rem_res.selected_candidate and (
                    rem_res.selected_candidate.candidate_id == candidate_id
                    or rem_res.selected_candidate.package_name == candidate_id
                ):
                    cand = rem_res.selected_candidate
                else:
                    for c in rem_res.candidates:
                        if c.candidate_id == candidate_id or c.package_name == candidate_id:
                            cand = c
                            break
            else:
                cand = rem_res.selected_candidate

            if not cand:
                continue

            # Ineligible candidates must not be processed for verification
            if (
                cand.strategy == RemediationStrategy.NO_SAFE_CANDIDATE
                or cand.status == CandidateStatus.CONTRADICTION_BLOCKED
                or cand.status == CandidateStatus.NO_SAFE_CANDIDATE
                or cand.status == CandidateStatus.REJECTED
                or (not cand.target_version and cand.strategy != RemediationStrategy.REMOVE_DEPENDENCY)
            ):
                logger.info(
                    "Skipping candidate %s (%s): not eligible for automated verification (status=%s, strategy=%s)",
                    cand.candidate_id,
                    cand.package_name,
                    cand.status,
                    cand.strategy,
                )
                continue

            target_finding = finding_map.get(rem_res.finding_id)
            if not target_finding:
                continue

            proof = cls.verify_candidate(
                repository_path=repo_dir,
                finding=target_finding,
                candidate=cand,
                mode=mode,
                before_graph=graph,
                test_status=test_status,
            )
            proof_results.append(proof)

            from acsa.proof.models import VerificationStatus
            if proof.verification_status == VerificationStatus.PROVEN_REMEDIATED:
                proven_count += 1
            elif proof.verification_status == VerificationStatus.REMEDIATION_PARTIALLY_VERIFIED:
                partially_count += 1
            elif proof.verification_status == VerificationStatus.REQUIRES_VERIFICATION:
                requires_count += 1
            elif proof.verification_status == VerificationStatus.REMEDIATION_FAILED:
                failed_count += 1

        has_contradictions = (
            any(
                c.status == CandidateStatus.CONTRADICTION_BLOCKED
                for r in rem_report.results
                for c in r.candidates
            )
            or any(r.verdict == Verdict.CONTRADICTORY for r in rem_report.results)
            or any(f.verdict == Verdict.CONTRADICTORY for f in scan_result.findings)
            or any(
                scan_result.inventory.has_version_discrepancy(pkg)
                for pkg in scan_result.inventory.unique_component_names
            )
        )

        if proof_results:
            summary = (
                f"Evaluated {len(proof_results)} remediation candidates under {mode.value}. "
                f"PROVEN_REMEDIATED: {proven_count}, REQUIRES_VERIFICATION: {requires_count}, "
                f"PARTIALLY_VERIFIED: {partially_count}, REMEDIATION_FAILED: {failed_count}."
            )
        else:
            if candidate_id:
                matched_cand = None
                for r in rem_report.results:
                    for c in r.candidates:
                        if c.candidate_id == candidate_id or c.package_name == candidate_id:
                            matched_cand = c
                            break
                    if matched_cand:
                        break

                if matched_cand and (
                    matched_cand.status == CandidateStatus.CONTRADICTION_BLOCKED
                    or has_contradictions
                ):
                    summary = (
                        f"No eligible remediation candidates verified for '{matched_cand.package_name}'. "
                        "Contradictory inventory observations detected across manifests and lockfiles "
                        "block automatic remediation. Manual review is required."
                    )
                elif matched_cand:
                    summary = (
                        f"Remediation candidate '{matched_cand.package_name}' cannot be verified: "
                        f"{matched_cand.reason}"
                    )
                else:
                    summary = f"No remediation candidate matching '{candidate_id}' was found for verification."
            elif has_contradictions:
                summary = (
                    "No eligible remediation candidates could be verified. "
                    "Contradictory inventory observations detected across manifests and lockfiles "
                    "block automatic remediation. Manual review is required."
                )
            else:
                summary = "No eligible remediation candidates were available for verification."

        return RemediationVerificationReport(
            repository_path=str(repo_dir),
            verification_mode=mode,
            total_candidates_verified=len(proof_results),
            proven_remediated_count=proven_count,
            partially_verified_count=partially_count,
            requires_verification_count=requires_count,
            failed_count=failed_count,
            results=proof_results,
            summary=summary,
        )
