"""Report generator formatting human-readable and machine-readable proof-carrying remediation bundles."""

from acsa.proof.models import ProofEvidence, RemediationVerificationReport


class ProofReportGenerator:
    """Generates human-readable terminal reports and serialized machine-readable proofs."""

    @classmethod
    def format_text_report(cls, evidence: ProofEvidence) -> str:
        """Format an individual ProofEvidence into the canonical ACSA proof report format."""
        before = evidence.before_snapshot
        after = evidence.after_snapshot
        cond = evidence.conditions
        comp = evidence.comparison

        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("ACSA PROOF-CARRYING REMEDIATION")
        lines.append("=" * 60)
        lines.append("")
        lines.append(f"Finding:\n  {evidence.finding_id}")
        lines.append(f"Component:\n  {evidence.target_component}")
        lines.append("")

        # BEFORE
        lines.append("BEFORE:")
        lines.append(f"  Version: {before.version or 'unversioned'}")
        lines.append(f"  Verdict: {before.verdict.value}")
        lines.append(f"  Reachability: {before.reachability_state}")
        lines.append(f"  Attacker control: {before.attacker_control_state}")
        if before.call_paths:
            lines.append("  Exposure Path:")
            for p in before.call_paths:
                lines.append(f"    {' -> '.join(p)}")
        elif before.vulnerable_call_sites:
            lines.append("  Vulnerable Call Sites:")
            for cs in before.vulnerable_call_sites:
                lines.append(f"    {cs}")
        lines.append("")

        # REMEDIATION
        lines.append("REMEDIATION:")
        lines.append(f"  Strategy: {evidence.strategy}")
        lines.append(f"  Candidate ID: {evidence.candidate_id}")
        if before.version and after.version:
            lines.append(f"  Change: {before.version} -> {after.version}")
        lines.append("")

        # AFTER
        lines.append("AFTER:")
        lines.append(f"  Version: {after.version or 'unversioned'}")
        lines.append(f"  Verdict: {after.verdict.value}")
        lines.append(f"  Reachability: {after.reachability_state}")
        lines.append(f"  Attacker control: {after.attacker_control_state}")
        lines.append("")

        # CONDITIONS
        lines.append("PROOF CONDITIONS:")
        lines.append(f"  1. Version: {'CLOSED (NOT_AFFECTED)' if cond.version_closed else 'OPEN / UNVERIFIED'}")
        lines.append(f"  2. Vulnerable Symbol: {'CLOSED / NOT_REACHABLE' if cond.vulnerable_symbol_closed else 'STILL ACTIVE'}")
        lines.append(f"  3. Exposure Path: {'SEVERED (ABSENT)' if cond.exposure_path_closed else 'PRESENT'}")
        lines.append(f"  4. Advisories: {len(comp.resolved_advisories)}/{len(before.advisories)} CLOSED")
        test_str = cond.test_status.value
        if cond.test_reason:
            test_str += f" ({cond.test_reason})"
        lines.append(f"  5. Tests: {test_str}")
        lines.append("")

        # COMPARISON DELTA
        lines.append(f"Delta Explanation:\n  {comp.delta_explanation}")
        lines.append("")

        # FINAL VERDICT
        lines.append("=" * 60)
        lines.append(f"FINAL VERIFICATION VERDICT: {evidence.verification_status.value}")
        if evidence.uncertainty_reason:
            lines.append(f"Uncertainty Reason: {evidence.uncertainty_reason}")
        if evidence.missing_evidence:
            lines.append(f"Missing Evidence: {evidence.missing_evidence}")
        lines.append("=" * 60)

        return "\n".join(lines)

    @classmethod
    def format_batch_summary(cls, report: RemediationVerificationReport) -> str:
        """Format an executive technical summary for a batch verification report."""
        lines: list[str] = []
        lines.append("=" * 60)
        lines.append("ACSA PROOF-CARRYING REMEDIATION SUMMARY")
        lines.append("=" * 60)
        lines.append(f"Repository: {report.repository_path}")
        lines.append(f"Verification Mode: {report.verification_mode.value}")
        lines.append(f"Total Evaluated Candidates: {report.total_candidates_verified}")
        lines.append(f"  PROVEN_REMEDIATED: {report.proven_remediated_count}")
        lines.append(f"  REQUIRES_VERIFICATION: {report.requires_verification_count}")
        lines.append(f"  PARTIALLY_VERIFIED: {report.partially_verified_count}")
        lines.append(f"  REMEDIATION_FAILED: {report.failed_count}")
        lines.append("=" * 60)
        return "\n".join(lines)
