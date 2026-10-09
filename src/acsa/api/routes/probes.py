"""API routes for Uncertainty-Guided Dynamic Probe Planning and Observation Evaluation."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from acsa.core.exceptions import PathTraversalError
from acsa.core.path_security import validate_safe_path
from acsa.probe.models import (
    ProbeEvaluation,
    ProbeObservation,
    ProbePlanReport,
    ProbeSpecification,
)
from acsa.probe.service import ProbeService
from acsa.verdict.vocabulary import Verdict

router = APIRouter(tags=["Dynamic Probe Planning"])


class PlanProbesRequest(BaseModel):
    """Request payload to initiate uncertainty-guided dynamic probe planning."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    repository_path: str = Field(
        description="Path to target repository workspace within authorized analysis boundary"
    )


class EvaluateProbeRequest(BaseModel):
    """Request payload to evaluate an empirical observation against a probe specification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    probe: ProbeSpecification = Field(
        description="Target probe specification previously planned by ACSA"
    )
    observation: ProbeObservation = Field(
        description="Structured empirical observation from analyst or instrumented test runner"
    )
    original_verdict: Verdict = Field(
        default=Verdict.UNKNOWN,
        description="Pre-observation verdict of the finding",
    )


@router.post(
    "/probes/plan",
    response_model=ProbePlanReport,
    status_code=status.HTTP_200_OK,
    summary="Generate targeted dynamic probe specifications for uncertain repository findings",
)
async def plan_probes(request: PlanProbesRequest) -> ProbePlanReport:
    """Analyze repository findings, determine missing evidence, and output prioritized safe probe specifications."""
    target_path = Path(request.repository_path)

    # Path traversal validation
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

    try:
        report, _ = ProbeService.plan_probes_for_repository(resolved_path)
        return report
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to plan dynamic probes: {err}",
        ) from err


@router.post(
    "/probes/evaluate",
    response_model=ProbeEvaluation,
    status_code=status.HTTP_200_OK,
    summary="Safely evaluate an empirical observation against a probe specification",
)
async def evaluate_probe(request: EvaluateProbeRequest) -> ProbeEvaluation:
    """Safely evaluate structured observation data against a probe specification without executing repository code."""
    try:
        evaluation = ProbeService.evaluate_observation(
            probe=request.probe,
            observation=request.observation,
            original_verdict=request.original_verdict,
        )
        return evaluation
    except Exception as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to evaluate probe observation: {err}",
        ) from err
