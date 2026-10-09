"""Base protocol and abstractions for artifact parsers."""

from abc import ABC, abstractmethod

from acsa.evidence.models import Evidence
from acsa.ingestion.models import DiscoveredArtifact, IngestionError, IngestionWarning
from acsa.inventory.models import Component, Dependency, InventoryObservation


class BaseArtifactParser(ABC):
    """Abstract base parser for repository dependency artifacts."""

    @abstractmethod
    def parse(
        self, artifact: DiscoveredArtifact
    ) -> tuple[
        list[InventoryObservation],
        list[Dependency],
        list[Component],
        list[Evidence],
        list[IngestionError],
        list[IngestionWarning],
    ]:
        """Parse a discovered artifact and return extracted observations, models, and diagnostics."""
        raise NotImplementedError
