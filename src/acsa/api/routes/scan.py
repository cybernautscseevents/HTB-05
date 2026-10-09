"""API route for repository vulnerability scanning and exact version applicability."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from acsa.context.service import ContextService
from acsa.core.exceptions import PathTraversalError
from acsa.core.path_security import validate_safe_path
from acsa.ingestion.service import IngestionService
from acsa.reachability.service import ReachabilityService
from acsa.verdict.service import EvidenceFusionService
from acsa.vulnerability.models import VulnerabilityScanResult
from acsa.vulnerability.service import VulnerabilityService

router = APIRouter(tags=["Vulnerability Scanning"])


class ScanRequest(BaseModel):
    """Request payload to initiate vulnerability scanning for a repository workspace."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    repository_path: str = Field(
        description="Path to target repository workspace within authorized analysis boundary"
    )


@router.post(
    "/scan",
    response_model=VulnerabilityScanResult,
    status_code=status.HTTP_200_OK,
    summary="Scan repository artifacts for exact-version vulnerability applicability via OSV, reachability, context, and verdicts",
)
async def scan_repository(request: ScanRequest) -> VulnerabilityScanResult:
    """Perform artifact ingestion, OSV intelligence matching, reachability, context data flow, and evidence fusion."""
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

    # 1. Artifact Ingestion
    ingest_service = IngestionService()
    ingest_result = ingest_service.ingest_repository(resolved_path)

    # 2. OSV Vulnerability Intelligence
    vuln_service = VulnerabilityService()
    scan_result = vuln_service.scan_inventory(
        ingest_result.inventory, repository_path=str(resolved_path)
    )

    # 3. Static Reachability Analysis
    reachability_service = ReachabilityService()
    findings_reach, reach_evidence, graph = reachability_service.analyze_findings(
        repository_path=resolved_path,
        findings=scan_result.findings,
    )

    # 4. Context & Attacker-Controlled Data Flow Analysis
    context_service = ContextService()
    findings_ctx, ctx_evidence = context_service.analyze_findings(
        repository_path=resolved_path,
        findings=findings_reach,
        graph=graph,
    )

    # Intermediate model with combined evidence
    intermediate_result = scan_result.model_copy(
        update={
            "findings": findings_ctx,
            "evidence": list(scan_result.evidence) + reach_evidence + ctx_evidence,
            "reachability_evaluated": True,
            "context_evaluated": True,
        }
    )

    # 5. Multi-Source Evidence Fusion & Verdict Determination
    fusion_service = EvidenceFusionService()
    final_result = fusion_service.enrich_scan_result(intermediate_result, graph=graph)
    return final_result
