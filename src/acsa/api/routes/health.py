"""Health check route for ACSA API."""

from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from acsa.core.config import get_settings

router = APIRouter(tags=["Health"])


class HealthResponse(BaseModel):
    """Health check response schema.

    Strictly reports service status; no mock or fake vulnerability metrics are returned.
    """

    model_config = ConfigDict(frozen=True, extra="forbid")

    status: str = Field(default="ok", description="Operational status of the service")
    service: str = Field(default="acsa-api", description="Service identifier")


@router.get("/health", response_model=HealthResponse)
async def get_health() -> dict[str, Any]:
    """Return current operational health of ACSA API."""
    settings = get_settings()
    return {
        "status": "ok",
        "service": settings.service_name,
    }
