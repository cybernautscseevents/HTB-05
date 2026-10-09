"""Remediation candidate generation and safe target version selection."""

import logging
from uuid import uuid4

from packaging.version import InvalidVersion
from packaging.version import Version as PackagingVersion

from acsa.remediation.models import (
    CandidateStatus,
    ClosureStatus,
    DependencyContext,
    DependencyRelation,
    EvidenceConfidence,
    RemediationCandidate,
    RemediationStrategy,
)
from acsa.verdict.vocabulary import Verdict
from acsa.vulnerability.models import Finding, Vulnerability

logger = logging.getLogger(__name__)


def parse_semver_safe(version_str: str | None) -> PackagingVersion | None:
    """Safely parse a version string into a PackagingVersion or return None."""
    if not version_str:
        return None
    v = version_str.strip().lstrip("v")
    try:
        return PackagingVersion(v)
    except InvalidVersion:
        return None


def is_version_affected_by_range(
    target_v: PackagingVersion,
    range_str: str,
) -> bool:
    """Check if target_v falls within a normalized range string (e.g. '>=1.0.0 <1.3.0' or '<1.3.0')."""
    parts = range_str.strip().split()
    lower_bound: PackagingVersion | None = None
    lower_inclusive = True
    upper_bound: PackagingVersion | None = None
    upper_inclusive = False

    for part in parts:
        if part.startswith(">="):
            lower_bound = parse_semver_safe(part[2:])
            lower_inclusive = True
        elif part.startswith(">"):
            lower_bound = parse_semver_safe(part[1:])
            lower_inclusive = False
        elif part.startswith("<="):
            upper_bound = parse_semver_safe(part[2:])
            upper_inclusive = True
        elif part.startswith("<"):
            upper_bound = parse_semver_safe(part[1:])
            upper_inclusive = False

    lower_ok = True
    if lower_bound is not None:
        lower_ok = (target_v >= lower_bound) if lower_inclusive else (target_v > lower_bound)

    upper_ok = True
    if upper_bound is not None:
        upper_ok = (target_v <= upper_bound) if upper_inclusive else (target_v < upper_bound)

    return lower_ok and upper_ok


def is_version_safe_against_advisories(
    cand_version: str,
    advisories: list[Vulnerability],
) -> tuple[bool, str | None]:
    """Verify whether a candidate version is non-vulnerable across ALL provided advisories.

    Returns (is_safe, failure_reason).
    """
    cand_v = parse_semver_safe(cand_version)
    if cand_v is None:
        return False, f"Candidate version '{cand_version}' is not valid semantic version"

    for adv in advisories:
        # Check against reported affected ranges (authoritative)
        if adv.affected_ranges:
            for rng in adv.affected_ranges:
                if is_version_affected_by_range(cand_v, rng):
                    return False, f"Version {cand_version} is affected by {adv.id} range '{rng}'"
        elif adv.fixed_versions:
            # Fallback when no range string provided: candidate must be >= at least one fixed version in same major
            fixed_vs = [parse_semver_safe(f) for f in adv.fixed_versions]
            valid_fixed = [fv for fv in fixed_vs if fv is not None]
            if valid_fixed:
                same_major_fixed = [fv for fv in valid_fixed if fv.major == cand_v.major]
                target_fixed = same_major_fixed if same_major_fixed else valid_fixed
                if all(cand_v < fv for fv in target_fixed):
                    return False, f"Version {cand_version} is lower than required fix {adv.fixed_versions[0]} for {adv.id}"

    return True, None


def select_minimum_safe_version(
    current_version: str,
    advisories: list[Vulnerability],
) -> str | None:
    """Identify the minimum non-vulnerable version satisfying ALL advisories for a package.

    Prefers the lowest semantic version jump (patch > minor > major), never blindly selecting 'latest'.
    """
    curr_v = parse_semver_safe(current_version)
    if curr_v is None:
        return None

    # Collect all candidate fixed versions from advisories
    candidate_versions_raw: set[str] = set()
    for adv in advisories:
        for f in adv.fixed_versions:
            if f.strip():
                candidate_versions_raw.add(f.strip())

    if not candidate_versions_raw:
        return None

    # Parse and filter candidate versions strictly > current_version
    valid_candidates: list[tuple[PackagingVersion, str]] = []
    for raw_v in candidate_versions_raw:
        pv = parse_semver_safe(raw_v)
        if pv is not None and pv > curr_v:
            # Check if this candidate satisfies ALL advisories
            is_safe, _ = is_version_safe_against_advisories(raw_v, advisories)
            if is_safe:
                valid_candidates.append((pv, raw_v))

    if not valid_candidates:
        return None

    # Sort candidates by PackagingVersion
    valid_candidates.sort(key=lambda item: item[0])

    # Preference 1: Minimum version within the same major version (lowest blast radius)
    same_major = [item for item in valid_candidates if item[0].major == curr_v.major]
    if same_major:
        # Preference 1a: Same minor version (patch bump)
        same_minor = [item for item in same_major if item[0].minor == curr_v.minor]
        if same_minor:
            return same_minor[0][1]
        return same_major[0][1]

    # Preference 2: Minimum safe version in next major
    return valid_candidates[0][1]


class CandidateGenerator:
    """Generates and evaluates defensible remediation candidates."""

    @classmethod
    def generate_candidates(
        cls,
        finding: Finding,
        dep_ctx: DependencyContext,
        all_package_advisories: list[Vulnerability] | None = None,
    ) -> list[RemediationCandidate]:
        """Generate ranked remediation candidates for an actionable finding."""
        advisories = all_package_advisories or [finding.vulnerability]
        candidates: list[RemediationCandidate] = []

        # 1. Contradictory inventory: block automated fix to prevent unsafe recommendation
        if finding.verdict == Verdict.CONTRADICTORY or dep_ctx.has_contradictions:
            blocked_cand = RemediationCandidate(
                candidate_id=str(uuid4()),
                strategy=RemediationStrategy.NO_SAFE_CANDIDATE,
                package_name=dep_ctx.package_name,
                current_version=dep_ctx.current_version,
                target_version=None,
                files_changed=[],
                dependencies_affected=[dep_ctx.package_name],
                api_impact="NONE",
                version_impact="NONE",
                closure_status=ClosureStatus.REQUIRES_VERIFICATION,
                confidence_level=EvidenceConfidence.LOW,
                lockfile_action="NONE",
                closed_advisories_count=0,
                total_advisories_count=len(advisories),
                closed_paths_count=0,
                total_paths_count=1,
                reason=(
                    f"Contradictory inventory detected for package '{dep_ctx.package_name}' across manifests and lockfiles. "
                    "Automated remediation is blocked to prevent applying an unsafe or mismatched fix."
                ),
                status=CandidateStatus.CONTRADICTION_BLOCKED,
                breaking_change_risk="high",
                finding_ids=[finding.id],
                evidence_ids=finding.evidence_ids,
                preconditions=["Reconcile manifest and lockfile version discrepancies manually"],
            )
            return [blocked_cand]

        # 2. Unused dependency: propose removal
        if dep_ctx.relation == DependencyRelation.UNUSED:
            manifest_file = dep_ctx.manifest_file or "package.json"
            remove_cand = RemediationCandidate(
                candidate_id=str(uuid4()),
                strategy=RemediationStrategy.REMOVE_DEPENDENCY,
                package_name=dep_ctx.package_name,
                current_version=dep_ctx.current_version,
                target_version=None,
                files_changed=[manifest_file],
                dependencies_affected=[dep_ctx.package_name],
                api_impact="NONE",
                version_impact="NONE",
                closure_status=ClosureStatus.PROVEN_CLOSED,
                confidence_level=EvidenceConfidence.HIGH,
                lockfile_action="LOCKFILE_REGENERATION_REQUIRED",
                closed_advisories_count=len(advisories),
                total_advisories_count=len(advisories),
                closed_paths_count=1,
                total_paths_count=1,
                reason=(
                    f"Component '{dep_ctx.package_name}' is declared in {manifest_file} but provably unreferenced "
                    "in application source code AST and imports. Safe to remove entirely."
                ),
                status=CandidateStatus.PROPOSED,
                breaking_change_risk="low",
                finding_ids=[finding.id],
                evidence_ids=finding.evidence_ids,
                expected_effect="Eliminates vulnerable dependency without modifying application source code.",
            )
            candidates.append(remove_cand)
            return candidates

        # 3. Find minimum safe target version
        safe_target_ver = select_minimum_safe_version(dep_ctx.current_version, advisories)

        if safe_target_ver is None:
            no_safe = RemediationCandidate(
                candidate_id=str(uuid4()),
                strategy=RemediationStrategy.NO_SAFE_CANDIDATE,
                package_name=dep_ctx.package_name,
                current_version=dep_ctx.current_version,
                target_version=None,
                files_changed=[],
                dependencies_affected=[dep_ctx.package_name],
                api_impact="NONE",
                version_impact="NONE",
                closure_status=ClosureStatus.REQUIRES_VERIFICATION,
                confidence_level=EvidenceConfidence.HIGH,
                lockfile_action="NONE",
                closed_advisories_count=0,
                total_advisories_count=len(advisories),
                closed_paths_count=0,
                total_paths_count=1,
                reason=(
                    f"No non-vulnerable version is available in upstream advisory intelligence for '{dep_ctx.package_name}' "
                    f"that resolves all {len(advisories)} known advisories."
                ),
                status=CandidateStatus.NO_SAFE_CANDIDATE,
                breaking_change_risk="high",
                finding_ids=[finding.id],
                evidence_ids=finding.evidence_ids,
            )
            return [no_safe]

        # Transparent evidence classification and closure status based on verdict
        is_unknown = finding.verdict in (Verdict.UNKNOWN, Verdict.NOT_VERIFIED)
        is_proven_exp = finding.verdict == Verdict.PROVEN_EXPOSURE
        is_potential = finding.verdict == Verdict.POTENTIALLY_AFFECTED

        if is_proven_exp:
            cand_closure = ClosureStatus.PROVEN_CLOSED
            cand_confidence = EvidenceConfidence.HIGH
            cand_status = CandidateStatus.PROPOSED
        elif is_potential:
            cand_closure = ClosureStatus.EXPECTED_TO_CLOSE
            cand_confidence = EvidenceConfidence.MEDIUM
            cand_status = CandidateStatus.PROPOSED
        else:
            cand_closure = ClosureStatus.REQUIRES_VERIFICATION
            cand_confidence = EvidenceConfidence.LOW
            cand_status = CandidateStatus.REQUIRES_CONFIRMATION

        curr_pv = parse_semver_safe(dep_ctx.current_version)
        target_pv = parse_semver_safe(safe_target_ver)

        is_patch = curr_pv and target_pv and curr_pv.major == target_pv.major and curr_pv.minor == target_pv.minor
        is_minor = curr_pv and target_pv and curr_pv.major == target_pv.major and curr_pv.minor != target_pv.minor

        if is_patch:
            version_impact = "PATCH"
            api_impact = "NONE"
            break_risk = "low"
        elif is_minor:
            version_impact = "MINOR"
            api_impact = "MINIMAL"
            break_risk = "low"
        else:
            version_impact = "MAJOR"
            api_impact = "SIGNIFICANT"
            break_risk = "high"

        # 4. Strategy generation based on relation
        if dep_ctx.relation == DependencyRelation.DIRECT:
            manifest_file = dep_ctx.manifest_file or "package.json"
            direct_cand = RemediationCandidate(
                candidate_id=str(uuid4()),
                strategy=RemediationStrategy.DIRECT_UPGRADE,
                package_name=dep_ctx.package_name,
                current_version=dep_ctx.current_version,
                target_version=safe_target_ver,
                files_changed=[manifest_file],
                dependencies_affected=[dep_ctx.package_name],
                api_impact=api_impact,
                version_impact=version_impact,
                closure_status=cand_closure,
                confidence_level=cand_confidence,
                lockfile_action="LOCKFILE_REGENERATION_REQUIRED",
                closed_advisories_count=len(advisories),
                total_advisories_count=len(advisories),
                closed_paths_count=1 if cand_closure != ClosureStatus.REQUIRES_VERIFICATION else 0,
                total_paths_count=1,
                reason=(
                    f"Upgrade direct dependency '{dep_ctx.package_name}' from {dep_ctx.current_version} to {safe_target_ver} "
                    f"(minimum safe version resolving all {len(advisories)} known advisories)."
                    + (" Note: Reachability is UNKNOWN; developer verification required." if is_unknown else "")
                ),
                status=cand_status,
                breaking_change_risk=break_risk,
                finding_ids=[finding.id],
                evidence_ids=finding.evidence_ids,
                expected_effect=f"Closes vulnerability {finding.vulnerability.id} with minimal dependency modification.",
            )
            candidates.append(direct_cand)

            # Propose API replacement candidate if vulnerable symbol is identified in a proven exposure
            if (
                finding.verdict == Verdict.PROVEN_EXPOSURE
                and finding.reachability
                and finding.reachability.status.value in ("REACHABLE", "POTENTIALLY_REACHABLE")
            ):
                calling_file = (
                    finding.reachability.call_site.split(":")[0]
                    if finding.reachability.call_site
                    else "app.js"
                )
                vuln_sym = (
                    finding.reachability.target_symbol
                    or (finding.vulnerability.vulnerable_symbols[0] if finding.vulnerability.vulnerable_symbols else "API")
                )

                api_cand = RemediationCandidate(
                    candidate_id=str(uuid4()),
                    strategy=RemediationStrategy.API_REPLACEMENT,
                    package_name=dep_ctx.package_name,
                    current_version=dep_ctx.current_version,
                    target_version=None,
                    files_changed=[calling_file],
                    dependencies_affected=[],
                    api_impact="SIGNIFICANT",
                    version_impact="NONE",
                    closure_status=ClosureStatus.PROVEN_CLOSED,
                    confidence_level=EvidenceConfidence.MEDIUM,
                    lockfile_action="NONE",
                    closed_advisories_count=len(advisories),
                    total_advisories_count=len(advisories),
                    closed_paths_count=1,
                    total_paths_count=1,
                    reason=(
                        f"Replace application usage of vulnerable symbol '{vuln_sym}' with safe application-level alternative "
                        f"in '{calling_file}'."
                    ),
                    status=CandidateStatus.PROPOSED,
                    breaking_change_risk="medium",
                    finding_ids=[finding.id],
                    evidence_ids=finding.evidence_ids,
                    expected_effect=f"Severs exposure path to '{vuln_sym}' without altering package manifest.",
                )
                candidates.append(api_cand)

        elif dep_ctx.relation == DependencyRelation.TRANSITIVE:
            # Candidate 1: Transitive override via package.json
            override_cand = RemediationCandidate(
                candidate_id=str(uuid4()),
                strategy=RemediationStrategy.TRANSITIVE_OVERRIDE,
                package_name=dep_ctx.package_name,
                current_version=dep_ctx.current_version,
                target_version=safe_target_ver,
                files_changed=["package.json"],
                dependencies_affected=[dep_ctx.package_name],
                api_impact="NONE",
                version_impact=version_impact,
                closure_status=cand_closure,
                confidence_level=cand_confidence,
                lockfile_action="LOCKFILE_REGENERATION_REQUIRED",
                closed_advisories_count=len(advisories),
                total_advisories_count=len(advisories),
                closed_paths_count=1 if cand_closure != ClosureStatus.REQUIRES_VERIFICATION else 0,
                total_paths_count=1,
                reason=(
                    f"Configure package manager override/resolution in package.json for transitive dependency '{dep_ctx.package_name}' "
                    f"to safe version {safe_target_ver}."
                    + (" Note: Reachability is UNKNOWN; developer verification required." if is_unknown else "")
                ),
                status=cand_status,
                breaking_change_risk="low",
                finding_ids=[finding.id],
                evidence_ids=finding.evidence_ids,
                expected_effect=f"Forces lockfile resolution of transitive '{dep_ctx.package_name}' to non-vulnerable version.",
            )
            candidates.append(override_cand)

            # Candidate 2: Parent package upgrade if parent is known
            if dep_ctx.parent_package:
                parent_cand = RemediationCandidate(
                    candidate_id=str(uuid4()),
                    strategy=RemediationStrategy.PARENT_UPGRADE,
                    package_name=dep_ctx.package_name,
                    current_version=dep_ctx.current_version,
                    target_version=safe_target_ver,
                    files_changed=["package.json"],
                    dependencies_affected=[dep_ctx.parent_package, dep_ctx.package_name],
                    api_impact="MINIMAL",
                    version_impact=version_impact,
                    closure_status=cand_closure,
                    confidence_level=EvidenceConfidence.MEDIUM,
                    lockfile_action="LOCKFILE_REGENERATION_REQUIRED",
                    closed_advisories_count=len(advisories),
                    total_advisories_count=len(advisories),
                    closed_paths_count=1 if cand_closure != ClosureStatus.REQUIRES_VERIFICATION else 0,
                    total_paths_count=1,
                    reason=(
                        f"Upgrade direct parent dependency '{dep_ctx.parent_package}' to version introducing safe transitive "
                        f"'{dep_ctx.package_name}@{safe_target_ver}'."
                    ),
                    status=cand_status,
                    breaking_change_risk="low",
                    finding_ids=[finding.id],
                    evidence_ids=finding.evidence_ids,
                    expected_effect=f"Eliminates vulnerable transitive '{dep_ctx.package_name}' through parent package update.",
                )
                candidates.append(parent_cand)
        else:
            # UNKNOWN relation
            unk_cand = RemediationCandidate(
                candidate_id=str(uuid4()),
                strategy=RemediationStrategy.DIRECT_UPGRADE,
                package_name=dep_ctx.package_name,
                current_version=dep_ctx.current_version,
                target_version=safe_target_ver,
                files_changed=["package.json"],
                dependencies_affected=[dep_ctx.package_name],
                api_impact=api_impact,
                version_impact=version_impact,
                closure_status=ClosureStatus.REQUIRES_VERIFICATION,
                confidence_level=EvidenceConfidence.LOW,
                lockfile_action="LOCKFILE_REGENERATION_REQUIRED",
                closed_advisories_count=len(advisories),
                total_advisories_count=len(advisories),
                closed_paths_count=0,
                total_paths_count=1,
                reason=f"Proposed upgrade for package '{dep_ctx.package_name}' with unverified dependency relation.",
                status=CandidateStatus.REQUIRES_CONFIRMATION,
                breaking_change_risk=break_risk,
                finding_ids=[finding.id],
                evidence_ids=finding.evidence_ids,
            )
            candidates.append(unk_cand)

        return candidates

    @classmethod
    def validate_candidate(
        cls,
        candidate: RemediationCandidate,
        finding: Finding,
        all_package_advisories: list[Vulnerability],
    ) -> tuple[bool, str]:
        """Validate candidate against all security advisories and exposure closure requirements.

        Rejects candidates that fail to resolve all advisories or fail to close proven exposure paths.
        """
        # Rule 1: Upgrade target version must resolve ALL known advisories
        if candidate.target_version:
            is_safe, reason = is_version_safe_against_advisories(
                candidate.target_version, all_package_advisories
            )
            if not is_safe:
                return False, f"Target version {candidate.target_version} fails advisory check: {reason}"

        # Rule 2: In PROVEN_EXPOSURE, candidate must sever the proven exposure path
        if finding.verdict == Verdict.PROVEN_EXPOSURE:
            if candidate.strategy == RemediationStrategy.REMOVE_DEPENDENCY:
                # Cannot remove a dependency actively called in proven exposure without breaking runtime
                return False, "Cannot apply REMOVE_DEPENDENCY on actively called package in proven exposure path"

            if candidate.strategy == RemediationStrategy.API_REPLACEMENT:
                # Must target the actual vulnerable symbol
                vuln_syms = set(finding.vulnerability.vulnerable_symbols)
                if vuln_syms:
                    # Check if candidate mentions the vulnerable symbol
                    if not any(sym in candidate.reason for sym in vuln_syms):
                        return False, f"API replacement does not target proven vulnerable symbol: {vuln_syms}"

        return True, "Candidate successfully validated against all advisories and exposure closure rules"
