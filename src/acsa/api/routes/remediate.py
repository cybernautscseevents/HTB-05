"""API route for Minimum-Blast-Radius remediation candidate generation."""

from pathlib import Path

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel, ConfigDict, Field

from acsa.context.service import ContextService
from acsa.core.exceptions import PathTraversalError
from acsa.core.path_security import validate_safe_path
from acsa.ingestion.service import IngestionService
from acsa.proof.models import EvidenceSnapshot, ProofConditions, VerificationMode
from acsa.reachability.service import ReachabilityService
from acsa.remediation.models import RemediationReport
from acsa.remediation.service import RemediationService
from acsa.verdict.service import EvidenceFusionService
from acsa.vulnerability.service import VulnerabilityService

router = APIRouter(tags=["Remediation Analysis"])


class RemediateRequest(BaseModel):
    """Request payload to initiate minimum-blast-radius remediation analysis."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    repository_path: str = Field(
        description="Path to target repository workspace within authorized analysis boundary"
    )


@router.post(
    "/remediate",
    response_model=RemediationReport,
    status_code=status.HTTP_200_OK,
    summary="Generate Minimum-Blast-Radius remediation candidates and simulated patches for repository findings",
)
async def remediate_repository(request: RemediateRequest) -> RemediationReport:
    """Analyze repository findings, determine dependency relations, select minimum safe versions, and simulate patches."""
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

    # 1. Ingestion
    ingest_service = IngestionService()
    ingest_result = ingest_service.ingest_repository(resolved_path)

    # 2. OSV Intelligence
    vuln_service = VulnerabilityService()
    scan_result = vuln_service.scan_inventory(
        ingest_result.inventory, repository_path=str(resolved_path)
    )

    # 3. Static Reachability
    reach_service = ReachabilityService()
    findings_reach, reach_ev, graph = reach_service.analyze_findings(
        resolved_path, scan_result.findings
    )

    # 4. Context & Attacker-Controlled Data Flow
    ctx_service = ContextService()
    findings_ctx, ctx_ev = ctx_service.analyze_findings(
        resolved_path, findings_reach, graph=graph
    )

    intermediate_result = scan_result.model_copy(
        update={
            "findings": findings_ctx,
            "evidence": list(scan_result.evidence) + reach_ev + ctx_ev,
            "reachability_evaluated": True,
            "context_evaluated": True,
        }
    )

    # 5. Evidence Fusion & Verdicts
    fusion_service = EvidenceFusionService()
    final_result = fusion_service.enrich_scan_result(intermediate_result, graph=graph)

    # 6. Minimum-Blast-Radius Remediation Analysis
    rem_service = RemediationService()
    rem_report = rem_service.remediate_repository(resolved_path, final_result)

    return rem_report


class VerifyRemediationRequest(BaseModel):
    """Request payload to initiate proof-carrying remediation verification."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    repository_path: str = Field(description="Path to target repository workspace")
    candidate_id: str | None = Field(default=None, description="Optional specific candidate ID to verify")
    mode: str = Field(default="MODE_A_SIMULATED", description="Verification mode: MODE_A_SIMULATED or MODE_B_MATERIALIZED")


class ProofVerificationItem(BaseModel):
    """Individual machine-verifiable proof verification outcome."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    candidate: str
    target_component: str
    strategy: str
    before: EvidenceSnapshot
    after: EvidenceSnapshot
    proof_conditions: ProofConditions
    evidence: list[str]
    verification_status: str
    uncertainty_reason: str | None = None
    missing_evidence: str | None = None
    final_verdict: str


class VerifyRemediationResponse(BaseModel):
    """Structured response containing machine-verifiable proofs."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    repository_path: str
    verification_mode: str
    total_candidates_verified: int
    proven_remediated_count: int
    requires_verification_count: int
    failed_count: int
    results: list[ProofVerificationItem]
    summary: str | None = None
    warning: str | None = None


@router.post(
    "/remediation/verify",
    response_model=VerifyRemediationResponse,
    status_code=status.HTTP_200_OK,
    summary="Verify remediation candidates and generate machine-verifiable proof packages",
)
async def verify_remediation(request: VerifyRemediationRequest) -> VerifyRemediationResponse:
    """Run Phase 6 Proof-Carrying Remediation verification across isolated workspaces."""
    from acsa.proof.service import RemediationProofService

    target_path = Path(request.repository_path)

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

    mode = (
        VerificationMode.MODE_B_MATERIALIZED
        if request.mode.upper() == "MODE_B_MATERIALIZED"
        else VerificationMode.MODE_A_SIMULATED
    )

    proof_report = RemediationProofService.verify_repository(
        repository_path=resolved_path,
        mode=mode,
        candidate_id=request.candidate_id,
    )

    items = [
        ProofVerificationItem(
            candidate=p.candidate_id,
            target_component=p.target_component,
            strategy=p.strategy,
            before=p.before_snapshot,
            after=p.after_snapshot,
            proof_conditions=p.conditions,
            evidence=p.evidence_ids,
            verification_status=p.verification_status.value,
            uncertainty_reason=p.uncertainty_reason,
            missing_evidence=p.missing_evidence,
            final_verdict=p.final_verdict.value,
        )
        for p in proof_report.results
    ]

    warning_msg: str | None = (
        proof_report.summary if proof_report.total_candidates_verified == 0 else None
    )

    return VerifyRemediationResponse(
        repository_path=proof_report.repository_path,
        verification_mode=proof_report.verification_mode.value,
        total_candidates_verified=proof_report.total_candidates_verified,
        proven_remediated_count=proof_report.proven_remediated_count,
        requires_verification_count=proof_report.requires_verification_count,
        failed_count=proof_report.failed_count,
        results=items,
        summary=proof_report.summary,
        warning=warning_msg,
    )
