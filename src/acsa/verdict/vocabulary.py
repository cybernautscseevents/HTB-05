"""Canonical verdict vocabulary for ACSA.

ACSA replaces ambiguous severity scores with evidence-backed exposure classifications.
CRITICAL PRINCIPLE: UNKNOWN must NEVER automatically mean SAFE.
"""

from enum import StrEnum


class Verdict(StrEnum):
    """Shared verdict vocabulary across all ACSA analysis and fusion phases."""

    PROVEN_EXPOSURE = "PROVEN_EXPOSURE"
    """Verified proof demonstrates that the vulnerable code or symbol is packaged,
    reachable, and exposed to external/attacker-controlled application execution paths."""

    PROVEN_AFFECTED = "PROVEN_AFFECTED"
    """The installed component version is confirmed affected by an advisory, while application-level
    exposure remains a separate conclusion (e.g. the vulnerable symbol is uninvoked or proven not
    reachable in application code). Package applicability alone must NEVER imply application exploitability."""

    POTENTIALLY_AFFECTED = "POTENTIALLY_AFFECTED"
    """Dependency is declared or resolved in the graph; reachability status remains pending
    or unconfirmed due to static analysis ambiguities."""

    PROVEN_NOT_AFFECTED = "PROVEN_NOT_AFFECTED"
    """Sufficient and verified evidence proves the vulnerable code is dead code, tree-shaken,
    excluded, or neutralized. THIS IS THE ONLY VERDICT THAT REPRESENTS PROVEN SAFETY."""

    UNKNOWN = "UNKNOWN"
    """Analysis is inconclusive due to missing artifacts, dynamic imports, reflection, or
    provider timeouts. MUST NEVER BE TREATED AS SAFE."""

    CONTRADICTORY = "CONTRADICTORY"
    """Discrepancies exist between manifest, lockfile, SBOM, or artifact observations that
    prevent establishing an authoritative ground truth without further reconciliation."""

    NOT_VERIFIED = "NOT_VERIFIED"
    """Candidate fix or component state has not undergone post-remediation verification."""

    @property
    def is_safe(self) -> bool:
        """Return True IF AND ONLY IF the artifact is conclusively proven not affected.

        UNKNOWN, POTENTIALLY_AFFECTED, and CONTRADICTORY are NOT safe.
        """
        return self == Verdict.PROVEN_NOT_AFFECTED

    @property
    def is_exposure(self) -> bool:
        """Return True if verified exposure has been proven."""
        return self == Verdict.PROVEN_EXPOSURE

    @property
    def is_conclusive(self) -> bool:
        """Return True if the analysis reached a conclusive definitive state."""
        return self in (
            Verdict.PROVEN_EXPOSURE,
            Verdict.PROVEN_AFFECTED,
            Verdict.PROVEN_NOT_AFFECTED,
        )

    @property
    def requires_investigation(self) -> bool:
        """Return True if deeper investigation or dynamic probing is warranted."""
        return self in (
            Verdict.POTENTIALLY_AFFECTED,
            Verdict.UNKNOWN,
            Verdict.CONTRADICTORY,
            Verdict.NOT_VERIFIED,
        )
