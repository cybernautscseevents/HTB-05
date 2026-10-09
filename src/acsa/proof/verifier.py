"""Proof verifier evaluating the 5 machine-verifiable closure conditions."""

from acsa.proof.models import (
    EvidenceSnapshot,
    ProofComparison,
    ProofConditions,
    TestValidationStatus,
    VerificationStatus,
)
from acsa.verdict.vocabulary import Verdict


class ProofVerifier:
    """Verifies whether machine-readable proof conditions are satisfied post-remediation."""

    @classmethod
    def evaluate(
        cls,
        before: EvidenceSnapshot,
        after: EvidenceSnapshot,
        comparison: ProofComparison,
        lockfile_not_regenerated: bool = False,
        test_status: TestValidationStatus = TestValidationStatus.NOT_EXECUTED,
        test_reason: str | None = "Repository command execution disabled by security policy.",
    ) -> tuple[ProofConditions, VerificationStatus, str | None, str | None]:
        """Evaluate proof conditions and determine authoritative VerificationStatus.

        Returns:
            (ProofConditions, VerificationStatus, uncertainty_reason, missing_evidence)
        """
        # Condition 1: Version closed
        # Version is closed if after.version is verified NOT_AFFECTED and lockfile was not blocked from regeneration
        version_closed = False
        if not lockfile_not_regenerated:
            if after.verdict == Verdict.PROVEN_NOT_AFFECTED:
                version_closed = True
            elif after.version and after.version != before.version:
                # Check that after version is not in affected advisories
                if not comparison.remaining_advisories:
                    version_closed = True
            elif before.verdict == Verdict.PROVEN_EXPOSURE and after.verdict != Verdict.PROVEN_EXPOSURE and not comparison.remaining_advisories:
                version_closed = True

        # Condition 2: Advisories closed
        advisories_closed = len(comparison.remaining_advisories) == 0 and len(comparison.resolved_advisories) > 0

        # If component had no advisories remaining in after state
        if not comparison.remaining_advisories and len(comparison.resolved_advisories) == len(before.advisories):
            advisories_closed = True

        # Condition 3: Vulnerable symbol closed
        vulnerable_symbol_closed = comparison.vulnerable_symbol_closed

        # Condition 4: Exposure path closed
        exposure_path_closed = comparison.exposure_path_severed

        # Condition 5: Test validation
        tests_validated = (test_status == TestValidationStatus.PASSED)

        conditions = ProofConditions(
            version_closed=version_closed,
            advisories_closed=advisories_closed,
            vulnerable_symbol_closed=vulnerable_symbol_closed,
            exposure_path_closed=exposure_path_closed,
            tests_validated=tests_validated,
            test_status=test_status,
            test_reason=test_reason,
        )

        # Authoritative VerificationStatus determination
        # Check 1: Contradictory evidence
        if after.verdict == Verdict.CONTRADICTORY or before.verdict == Verdict.CONTRADICTORY:
            return (
                conditions,
                VerificationStatus.CONTRADICTORY,
                "Contradictory inventory or conflicting evidence signals prevent a trustworthy proof conclusion.",
                "Resolved dependency state across all manifests and lockfiles.",
            )

        # Check 2: Lockfile not regenerated (MODE A safety restriction)
        if lockfile_not_regenerated:
            return (
                conditions,
                VerificationStatus.REQUIRES_VERIFICATION,
                "Manifest change proposed but lockfile regeneration was not executed to avoid running untrusted scripts.",
                "Regenerated package-lock.json (run `npm install --package-lock-only`) to confirm exact post-remediation version.",
            )

        # Check 3: Tests explicitly failed
        if test_status == TestValidationStatus.FAILED:
            return (
                conditions,
                VerificationStatus.REMEDIATION_FAILED,
                "Repository tests failed after applying remediation candidate.",
                None,
            )

        # Check 4: Remediation failed (vulnerability or exposure still active)
        if comparison.remaining_advisories:
            return (
                conditions,
                VerificationStatus.REMEDIATION_FAILED,
                f"Remediation failed to resolve all advisories: {', '.join(comparison.remaining_advisories)} remain active.",
                None,
            )

        if after.verdict == Verdict.PROVEN_EXPOSURE:
            return (
                conditions,
                VerificationStatus.REMEDIATION_FAILED,
                "Post-remediation analysis still confirms attacker-controlled exposure to vulnerable sink.",
                None,
            )

        # Check 5: Reachability or verdict remains UNKNOWN
        if after.verdict == Verdict.UNKNOWN or (
            after.verdict != Verdict.PROVEN_NOT_AFFECTED and after.reachability_state == "UNKNOWN"
        ):
            return (
                conditions,
                VerificationStatus.REQUIRES_VERIFICATION,
                "Post-remediation reachability remains UNKNOWN; automated proof cannot be established without dynamic verification.",
                "Runtime trace or dynamic probe confirming vulnerable symbol is unreachable.",
            )

        # Check 6: All required machine-verifiable conditions satisfied
        if (
            version_closed
            and advisories_closed
            and vulnerable_symbol_closed
            and exposure_path_closed
        ):
            return (
                conditions,
                VerificationStatus.PROVEN_REMEDIATED,
                None,
                None,
            )

        # Check 7: Partial verification
        if advisories_closed or exposure_path_closed:
            return (
                conditions,
                VerificationStatus.REMEDIATION_PARTIALLY_VERIFIED,
                "Remediation partially verified: some closure conditions met but full proof conditions not completed.",
                "Empirical confirmation of all closure conditions.",
            )

        return (
            conditions,
            VerificationStatus.NOT_VERIFIED,
            "Insufficient evidence to verify remediation candidate.",
            "Complete before/after evidence artifacts.",
        )
