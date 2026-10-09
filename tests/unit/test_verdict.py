"""Unit tests for the canonical ACSA verdict vocabulary and safety invariants."""

import pytest

from acsa.verdict.vocabulary import Verdict


def test_verdict_vocabulary_completeness() -> None:
    """Verify all 7 mandatory verdict vocabulary statuses are defined."""
    expected_statuses = {
        "PROVEN_EXPOSURE",
        "PROVEN_AFFECTED",
        "POTENTIALLY_AFFECTED",
        "PROVEN_NOT_AFFECTED",
        "UNKNOWN",
        "CONTRADICTORY",
        "NOT_VERIFIED",
    }
    actual_statuses = {v.value for v in Verdict}
    assert actual_statuses == expected_statuses


def test_unknown_must_never_mean_safe() -> None:
    """CRITICAL SAFETY INVARIANT: UNKNOWN must NEVER be interpreted as SAFE."""
    assert Verdict.UNKNOWN.is_safe is False
    safe_verdicts = {v for v in Verdict if v.is_safe}
    assert Verdict.UNKNOWN not in safe_verdicts


@pytest.mark.parametrize(
    ("verdict", "expected_safe"),
    [
        (Verdict.PROVEN_EXPOSURE, False),
        (Verdict.PROVEN_AFFECTED, False),
        (Verdict.POTENTIALLY_AFFECTED, False),
        (Verdict.PROVEN_NOT_AFFECTED, True),
        (Verdict.UNKNOWN, False),
        (Verdict.CONTRADICTORY, False),
        (Verdict.NOT_VERIFIED, False),
    ],
)
def test_only_proven_not_affected_is_safe(verdict: Verdict, expected_safe: bool) -> None:
    """Verify that only PROVEN_NOT_AFFECTED evaluates to safe."""
    assert verdict.is_safe == expected_safe


def test_proven_exposure_properties() -> None:
    """Verify exposure and conclusiveness semantics."""
    assert Verdict.PROVEN_EXPOSURE.is_exposure is True
    assert Verdict.PROVEN_AFFECTED.is_exposure is False
    assert Verdict.PROVEN_EXPOSURE.is_conclusive is True
    assert Verdict.PROVEN_NOT_AFFECTED.is_conclusive is True
    assert Verdict.UNKNOWN.is_conclusive is False


def test_requires_investigation_property() -> None:
    """Verify that ambiguous or contradictory states require investigation."""
    assert Verdict.UNKNOWN.requires_investigation is True
    assert Verdict.CONTRADICTORY.requires_investigation is True
    assert Verdict.POTENTIALLY_AFFECTED.requires_investigation is True
    assert Verdict.NOT_VERIFIED.requires_investigation is True
    assert Verdict.PROVEN_EXPOSURE.requires_investigation is False
    assert Verdict.PROVEN_NOT_AFFECTED.requires_investigation is False
