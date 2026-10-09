"""Unit tests for exact-version applicability evaluation."""

from acsa.vulnerability.applicability import ApplicabilityEvaluator
from acsa.vulnerability.models import ApplicabilityStatus


def test_applicability_explicit_version_match() -> None:
    """Exact version explicitly listed in versions list is classified as AFFECTED."""
    advisory = {
        "id": "GHSA-test-1",
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "versions": ["4.17.19", "4.17.20"],
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.17.21"}]}],
            }
        ],
    }

    res = ApplicabilityEvaluator.evaluate("4.17.19", advisory, package_name="lodash")
    assert res.status == ApplicabilityStatus.AFFECTED
    assert "4.17.21" in res.fixed_versions
    assert "explicitly listed" in res.explanation


def test_applicability_range_match_affected() -> None:
    """Exact version inside [introduced, fixed) is classified as AFFECTED."""
    advisory = {
        "id": "GHSA-test-2",
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "4.0.0"},
                            {"fixed": "4.17.21"},
                        ],
                    }
                ],
            }
        ],
    }

    res = ApplicabilityEvaluator.evaluate("4.17.19", advisory, package_name="lodash")
    assert res.status == ApplicabilityStatus.AFFECTED
    assert "4.17.21" in res.fixed_versions


def test_applicability_fixed_version_is_not_affected() -> None:
    """Exact version at or above fixed version is classified as NOT_AFFECTED."""
    advisory = {
        "id": "GHSA-test-3",
        "affected": [
            {
                "package": {"name": "lodash", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "0"},
                            {"fixed": "4.17.21"},
                        ],
                    }
                ],
            }
        ],
    }

    # Fixed version itself: NOT_AFFECTED
    res_fixed = ApplicabilityEvaluator.evaluate("4.17.21", advisory, package_name="lodash")
    assert res_fixed.status == ApplicabilityStatus.NOT_AFFECTED

    # Version after fixed: NOT_AFFECTED
    res_newer = ApplicabilityEvaluator.evaluate("4.17.22", advisory, package_name="lodash")
    assert res_newer.status == ApplicabilityStatus.NOT_AFFECTED


def test_applicability_version_prior_to_introduction_is_not_affected() -> None:
    """Exact version before introduced version is classified as NOT_AFFECTED."""
    advisory = {
        "id": "GHSA-test-4",
        "affected": [
            {
                "package": {"name": "semver", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "7.0.0"},
                            {"fixed": "7.5.2"},
                        ],
                    }
                ],
            }
        ],
    }

    res = ApplicabilityEvaluator.evaluate("6.3.0", advisory, package_name="semver")
    assert res.status == ApplicabilityStatus.NOT_AFFECTED


def test_applicability_multiple_ranges_and_intervals() -> None:
    """Evaluate complex advisories with multiple [introduced, fixed) intervals."""
    advisory = {
        "id": "GHSA-multi-range",
        "affected": [
            {
                "package": {"name": "complex-pkg", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.5.0"},
                            {"introduced": "2.0.0"},
                            {"fixed": "2.3.0"},
                        ],
                    }
                ],
            }
        ],
    }

    # Affected in interval 1
    res1 = ApplicabilityEvaluator.evaluate("1.2.0", advisory, package_name="complex-pkg")
    assert res1.status == ApplicabilityStatus.AFFECTED

    # Fixed in interval 1
    res1_fix = ApplicabilityEvaluator.evaluate("1.5.0", advisory, package_name="complex-pkg")
    assert res1_fix.status == ApplicabilityStatus.NOT_AFFECTED

    # In-between interval 1 and interval 2
    res_between = ApplicabilityEvaluator.evaluate("1.8.0", advisory, package_name="complex-pkg")
    assert res_between.status == ApplicabilityStatus.NOT_AFFECTED

    # Affected in interval 2
    res2 = ApplicabilityEvaluator.evaluate("2.1.0", advisory, package_name="complex-pkg")
    assert res2.status == ApplicabilityStatus.AFFECTED

    # Fixed in interval 2
    res2_fix = ApplicabilityEvaluator.evaluate("2.3.0", advisory, package_name="complex-pkg")
    assert res2_fix.status == ApplicabilityStatus.NOT_AFFECTED

    # After all intervals
    res_after = ApplicabilityEvaluator.evaluate("3.0.0", advisory, package_name="complex-pkg")
    assert res_after.status == ApplicabilityStatus.NOT_AFFECTED


def test_applicability_last_affected_event() -> None:
    """Verify inclusive last_affected events properly classify boundary versions."""
    advisory = {
        "id": "GHSA-last-affected",
        "affected": [
            {
                "package": {"name": "target-pkg", "ecosystem": "npm"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"last_affected": "1.2.3"},
                        ],
                    }
                ],
            }
        ],
    }

    # Inside range
    assert ApplicabilityEvaluator.evaluate("1.2.0", advisory, package_name="target-pkg").status == ApplicabilityStatus.AFFECTED
    # Exactly last_affected version (inclusive)
    assert ApplicabilityEvaluator.evaluate("1.2.3", advisory, package_name="target-pkg").status == ApplicabilityStatus.AFFECTED
    # After last_affected version
    assert ApplicabilityEvaluator.evaluate("1.2.4", advisory, package_name="target-pkg").status == ApplicabilityStatus.NOT_AFFECTED


def test_applicability_package_mismatch_is_not_affected() -> None:
    """Advisory targeting a different package returns NOT_AFFECTED."""
    advisory = {
        "id": "GHSA-test-5",
        "affected": [
            {
                "package": {"name": "express", "ecosystem": "npm"},
                "ranges": [{"events": [{"introduced": "0"}, {"fixed": "4.19.2"}]}],
            }
        ],
    }

    res = ApplicabilityEvaluator.evaluate("1.0.0", advisory, package_name="lodash")
    assert res.status == ApplicabilityStatus.NOT_AFFECTED


def test_applicability_invalid_version_is_unknown() -> None:
    """Unparseable or ambiguous version returns UNKNOWN (UNKNOWN != SAFE)."""
    advisory = {
        "id": "GHSA-test-6",
        "affected": [
            {
                "package": {"name": "foo", "ecosystem": "npm"},
                "ranges": [{"events": [{"introduced": "1.0.0"}, {"fixed": "2.0.0"}]}],
            }
        ],
    }

    res = ApplicabilityEvaluator.evaluate("not-a-valid-semver-at-all", advisory, package_name="foo")
    assert res.status == ApplicabilityStatus.UNKNOWN


def test_applicability_unparseable_range_event_is_unknown() -> None:
    """Advisory with unparseable range events produces UNKNOWN instead of false safe."""
    advisory = {
        "id": "GHSA-test-corrupt-range",
        "affected": [
            {
                "package": {"name": "corrupt-pkg", "ecosystem": "npm"},
                "ranges": [{"events": [{"introduced": "not.a.version"}, {"fixed": "also.bad"}]}],
            }
        ],
    }

    res = ApplicabilityEvaluator.evaluate("1.0.0", advisory, package_name="corrupt-pkg")
    assert res.status == ApplicabilityStatus.UNKNOWN
