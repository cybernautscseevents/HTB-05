"""Deterministic minimum-blast-radius ranking and explanation generation."""

import logging

from acsa.remediation.models import (
    CandidateStatus,
    ClosureStatus,
    EvidenceConfidence,
    RemediationCandidate,
    RemediationStrategy,
)
from acsa.verdict.vocabulary import Verdict
from acsa.vulnerability.models import Finding

logger = logging.getLogger(__name__)


class RemediationRanker:
    """Ranks remediation candidates based on Minimum-Blast-Radius criteria."""

    @classmethod
    def rank_candidates(
        cls,
        candidates: list[RemediationCandidate],
        finding: Finding | None = None,
    ) -> list[RemediationCandidate]:
        """Deterministically sort candidates prioritizing minimal surface area change and proven exposure closure."""
        if not candidates:
            return []

        def sort_key(c: RemediationCandidate) -> tuple[int, int, int, int, int, int, int, int, int]:
            # 1. Candidate status priority (actionable first, uncertain second, blocked/rejected last)
            if c.status in (CandidateStatus.PROPOSED, CandidateStatus.ACCEPTED):
                status_rank = 0
            elif c.status == CandidateStatus.REQUIRES_CONFIRMATION:
                status_rank = 1
            else:
                status_rank = 2

            # 2. Exposure closure priority: PROVEN_CLOSED (0) < EXPECTED_TO_CLOSE (1) < REQUIRES_VERIFICATION (2)
            closure_rank = {
                ClosureStatus.PROVEN_CLOSED: 0,
                ClosureStatus.EXPECTED_TO_CLOSE: 1,
                ClosureStatus.REQUIRES_VERIFICATION: 2,
            }.get(c.closure_status, 1)

            # 3. Unresolved advisories count (0 is best, i.e. candidate resolves all advisories)
            unresolved_advs = max(0, c.total_advisories_count - c.closed_advisories_count)

            # 4. Source file changes (0 source code edits preferred over modifying application code)
            source_changes = len([f for f in c.files_changed if not f.endswith(".json")])

            # 5. Strategy hierarchy (safest first)
            strat_order = {
                RemediationStrategy.REMOVE_DEPENDENCY: 0,
                RemediationStrategy.DIRECT_UPGRADE: 1,
                RemediationStrategy.TRANSITIVE_OVERRIDE: 2,
                RemediationStrategy.PARENT_UPGRADE: 3,
                RemediationStrategy.CONFIG_MITIGATION: 4,
                RemediationStrategy.API_REPLACEMENT: 5,
                RemediationStrategy.NO_SAFE_CANDIDATE: 9,
            }.get(c.strategy, 6)

            # 6. Version jump impact: NONE (0) < PATCH (1) < MINOR (2) < MAJOR (3) < UNKNOWN (4)
            version_rank = {
                "NONE": 0,
                "PATCH": 1,
                "MINOR": 2,
                "MAJOR": 3,
                "UNKNOWN": 4,
            }.get(c.version_impact.upper(), 2)

            # 7. Total dependencies affected (fewer is better)
            dep_count = len(c.dependencies_affected)

            # 8. API compatibility impact: NONE (0) < MINIMAL (1) < SIGNIFICANT (2)
            api_rank = {
                "NONE": 0,
                "MINIMAL": 1,
                "SIGNIFICANT": 2,
            }.get(c.api_impact.upper(), 1)

            # 9. Evidence classification: HIGH (0) < MEDIUM (1) < LOW (2)
            conf_rank = {
                EvidenceConfidence.HIGH: 0,
                EvidenceConfidence.MEDIUM: 1,
                EvidenceConfidence.LOW: 2,
            }.get(c.confidence_level, 1)

            return (
                status_rank,
                closure_rank,
                unresolved_advs,
                source_changes,
                strat_order,
                version_rank,
                dep_count,
                api_rank,
                conf_rank,
            )

        ranked = sorted(candidates, key=sort_key)

        # Mark top valid candidate as ACCEPTED if it was PROPOSED
        updated_list: list[RemediationCandidate] = []
        has_accepted = False

        for idx, c in enumerate(ranked):
            if idx == 0 and c.status == CandidateStatus.PROPOSED and not has_accepted:
                updated_cand = c.model_copy(update={"status": CandidateStatus.ACCEPTED})
                updated_list.append(updated_cand)
                has_accepted = True
            else:
                updated_list.append(c)

        return updated_list

    @classmethod
    def generate_explanation(
        cls,
        candidate: RemediationCandidate,
        finding: Finding | None = None,
        alternatives: list[RemediationCandidate] | None = None,
    ) -> str:
        """Construct a human-readable, evidence-grounded blast-radius rationale."""
        lines: list[str] = []
        lines.append(f"Candidate: {candidate.strategy.value} for {candidate.package_name}")

        if candidate.target_version:
            lines.append(f"  Target Version: {candidate.target_version} (current: {candidate.current_version})")

        if candidate.reason:
            lines.append(f"  - Rationale: {candidate.reason}")

        # Files and dependencies
        source_files = [f for f in candidate.files_changed if not f.endswith(".json")]
        manifest_files = [f for f in candidate.files_changed if f.endswith(".json")]

        lines.append(f"  - Advisories resolved: {candidate.closed_advisories_count}/{candidate.total_advisories_count} relevant advisories")
        lines.append(f"  - Exposure closure: {candidate.closure_status.value} ({candidate.closed_paths_count}/{candidate.total_paths_count} proven paths)")
        lines.append(f"  - Application source files changed: {len(source_files)}")
        lines.append(f"  - Manifest/lockfile edits: {len(manifest_files)}")
        lines.append(f"  - Package dependencies affected: {len(candidate.dependencies_affected)} ({', '.join(candidate.dependencies_affected)})")
        lines.append(f"  - Version change impact: {candidate.version_impact.lower()}")
        lines.append(f"  - API compatibility impact: {candidate.api_impact.lower()}")
        lines.append(f"  - Breaking change risk: {candidate.breaking_change_risk}")
        lines.append(f"  - Lockfile action: {candidate.lockfile_action}")
        lines.append(f"  - Evidence classification: {candidate.confidence_level.value}")

        if finding:
            if finding.verdict == Verdict.PROVEN_EXPOSURE:
                vuln_sym = finding.vulnerability.vulnerable_symbols[0] if finding.vulnerability.vulnerable_symbols else "affected API"
                lines.append(f"  - Closes proven exposure path: severs data flow to vulnerable symbol '{vuln_sym}'")
            elif finding.verdict == Verdict.PROVEN_AFFECTED:
                lines.append("  - Note: Vulnerable symbol is not reachable in application code (PROVEN_AFFECTED); lower remediation urgency")
            elif finding.verdict == Verdict.UNKNOWN:
                lines.append("  - Note: Reachability is UNKNOWN; automated fix requires developer confirmation")

        # Explain why preferred over alternatives if alternatives exist
        if alternatives:
            other_valid = [a for a in alternatives if a.candidate_id != candidate.candidate_id and a.status != CandidateStatus.REJECTED]
            if other_valid:
                lines.append("  - Preferred over alternatives because:")
                for alt in other_valid:
                    if alt.strategy == RemediationStrategy.API_REPLACEMENT:
                        lines.append(f"    * vs {alt.strategy.value}: Avoids application source code modifications and behavioral regressions")
                    elif alt.strategy == RemediationStrategy.PARENT_UPGRADE:
                        lines.append(f"    * vs {alt.strategy.value}: Targets specific dependency directly without modifying parent dependencies")
                    elif alt.version_impact == "MAJOR" and candidate.version_impact != "MAJOR":
                        lines.append(f"    * vs {alt.strategy.value} ({alt.target_version}): Preserves major version branch avoiding breaking changes")
                    else:
                        lines.append(f"    * vs {alt.strategy.value}: Lower dependency and application disruption")

        return "\n".join(lines)
