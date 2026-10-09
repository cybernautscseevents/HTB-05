"""Ingestion layer contracts for repository intake and snapshotting."""

from acsa.ingestion.discovery import ArtifactDiscovery
from acsa.ingestion.models import (
    ArtifactType,
    DiscoveredArtifact,
    IngestionError,
    IngestionResult,
    IngestionWarning,
    Repository,
    RepositorySnapshot,
)
from acsa.ingestion.service import IngestionService

__all__ = [
    "ArtifactDiscovery",
    "ArtifactType",
    "DiscoveredArtifact",
    "IngestionError",
    "IngestionResult",
    "IngestionService",
    "IngestionWarning",
    "Repository",
    "RepositorySnapshot",
]
