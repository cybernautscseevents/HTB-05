"""API route for repository artifact ingestion."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from acsa.core.exceptions import PathTraversalError
from acsa.core.path_security import validate_safe_path
from acsa.ingestion.models import IngestionResult
from acsa.ingestion.service import IngestionService

router = APIRouter(tags=["Ingestion"])


class IngestRequest(BaseModel):
    """Request payload to initiate artifact ingestion for a repository workspace."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    repository_path: str = Field(
        description="Path to target repository workspace within authorized analysis boundary"
    )


@router.post(
    "/ingest",
    response_model=IngestionResult,
    status_code=status.HTTP_200_OK,
    summary="Ingest dependency manifests, lockfiles, and SBOMs from a workspace",
)
async def ingest_repository(request: IngestRequest) -> IngestionResult:
    """Safely discover and parse supported dependency artifacts in the repository workspace."""
    target_path = Path(request.repository_path)

    # Enforce Phase 0 path security boundary: prevent path traversal and arbitrary filesystem escapes
    try:
        resolved_path = validate_safe_path(target_path, target_path)
    except PathTraversalError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Path security violation: {err}",
        ) from err
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid repository path: {err}",
        ) from err

    if not resolved_path.exists() or not resolved_path.is_dir():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Repository workspace directory not found: '{request.repository_path}'",
        )

    service = IngestionService()
    result = service.ingest_repository(resolved_path)
    return result
