"""FastAPI application factory for ACSA API."""

from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from acsa.api.routes.health import router as health_router
from acsa.api.routes.ingest import router as ingest_router
from acsa.api.routes.probes import router as probes_router
from acsa.api.routes.remediate import router as remediate_router
from acsa.api.routes.scan import router as scan_router
from acsa.core.config import get_settings
from acsa.core.logging import setup_logging


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan context manager for application startup and shutdown events."""
    settings = get_settings()
    setup_logging(settings.log_level)
    yield


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    settings = get_settings()

    app = FastAPI(
        title="ACSA — Artifact-Centric Security Analysis API",
        description="Evidence-driven software supply chain security platform",
        version="0.1.0",
        lifespan=lifespan,
    )

    # Restrictive CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"] if settings.env == "development" else [],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # Health check endpoints
    app.include_router(health_router)
    app.include_router(health_router, prefix="/api/v1")

    # Ingestion endpoints
    app.include_router(ingest_router)
    app.include_router(ingest_router, prefix="/api/v1")

    # Scanning & Intelligence endpoints
    app.include_router(scan_router)
    app.include_router(scan_router, prefix="/api/v1")

    # Remediation endpoints
    app.include_router(remediate_router)
    app.include_router(remediate_router, prefix="/api/v1")

    # Dynamic Probe endpoints
    app.include_router(probes_router)
    app.include_router(probes_router, prefix="/api/v1")

    return app


app = create_app()
