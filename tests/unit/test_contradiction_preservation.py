"""Unit tests verifying Contradiction-Aware Inventory preservation (Novelty 3)."""

from pathlib import Path

from acsa.evidence.models import EvidenceSource
from acsa.ingestion.service import IngestionService

FIXTURES_DIR = Path(__file__).resolve().parent.parent / "fixtures"


def test_contradictory_fixture_preserves_all_three_observations() -> None:
    """CRITICAL TEST FOR NOVELTY 3: Contradiction-Aware Inventory.

    Verify that conflicting observations across package.json, package-lock.json, and bom.json
    are NOT collapsed into a single value, but rather preserved independently.
    """
    repo_path = FIXTURES_DIR / "repo_contradictory"
    service = IngestionService()
    result = service.ingest_repository(repo_path)

    assert result.success is True
    assert len(result.discovered_artifacts) == 3

    # Retrieve all independent observations for lodash
    lodash_obs = result.inventory.get_observations_for_component("lodash")
    assert len(lodash_obs) == 3, f"Expected 3 independent observations for lodash, got {len(lodash_obs)}"

    # Check that each source observation is preserved exactly
    obs_by_source = {obs.source_type: obs for obs in lodash_obs}

    # 1. package.json observation
    assert EvidenceSource.PACKAGE_JSON in obs_by_source
    pkg_obs = obs_by_source[EvidenceSource.PACKAGE_JSON]
    assert pkg_obs.version_constraint == "^4.17.20"
    assert pkg_obs.version is None

    # 2. package-lock.json observation
    assert EvidenceSource.PACKAGE_LOCK in obs_by_source
    lock_obs = obs_by_source[EvidenceSource.PACKAGE_LOCK]
    assert lock_obs.version == "4.17.21"

    # 3. bom.json observation
    assert EvidenceSource.CYCLONEDX_SBOM in obs_by_source
    sbom_obs = obs_by_source[EvidenceSource.CYCLONEDX_SBOM]
    assert sbom_obs.version == "4.17.19"

    # Check discrepancy detection helper
    assert result.inventory.has_version_discrepancy("lodash") is True
    observed_versions = result.inventory.get_observed_versions("lodash")
    assert observed_versions == {"4.17.21", "4.17.19"}

    # Ensure metric reflects discrepancy
    assert result.metrics["components_with_version_discrepancy"] == 1
