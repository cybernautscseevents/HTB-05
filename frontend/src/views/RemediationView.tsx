import React, { useState } from 'react';
import type { RemediationReport, VerifyRemediationResponse } from '../types/api';
import { acsaApi } from '../api/client';
import { ProofConditionsTable } from '../components/ProofConditionsTable';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState } from '../components/EmptyState';
import { LoadingState } from '../components/LoadingState';

interface RemediationViewProps {
  repositoryPath: string;
  remediationReport: RemediationReport | null;
  onGenerateRemediation: () => void;
  isLoading: boolean;
}

export const RemediationView: React.FC<RemediationViewProps> = ({
  repositoryPath,
  remediationReport,
  onGenerateRemediation,
  isLoading,
}) => {
  const [verifyingCandidateId, setVerifyingCandidateId] = useState<string | null>(null);
  const [verificationResponse, setVerificationResponse] = useState<VerifyRemediationResponse | null>(null);
  const [verificationError, setVerificationError] = useState<string | null>(null);
  const [verificationNotice, setVerificationNotice] = useState<string | null>(null);

  const candidates =
    remediationReport?.candidates && remediationReport.candidates.length > 0
      ? remediationReport.candidates
      : remediationReport?.results
        ? remediationReport.results.flatMap((r) => (r.selected_candidate ? [r.selected_candidate] : r.candidates))
        : [];

  const candidatesGenerated =
    remediationReport?.candidates_generated ?? candidates.length;

  const totalFindingsEvaluated =
    remediationReport?.total_findings_evaluated ?? remediationReport?.results?.length ?? 0;

  const hasContradictions =
    (remediationReport?.contradictions_detected ?? 0) > 0 ||
    (remediationReport?.results?.some((r) => r.verdict === 'CONTRADICTORY') ?? false) ||
    candidates.some(
      (c) =>
        c.status === 'CONTRADICTION_BLOCKED' ||
        c.strategy === 'NO_SAFE_CANDIDATE'
    );

  const requiresLockfileRegen =
    remediationReport?.lockfile_regeneration_required ??
    candidates.some(
      (c) =>
        c.lockfile_action === 'REGENERATION_REQUIRED' ||
        c.strategy === 'DIRECT_UPGRADE' ||
        c.strategy === 'TRANSITIVE_OVERRIDE'
    );

  const handleVerify = async (candidateId?: string) => {
    if (!repositoryPath) return;
    setVerifyingCandidateId(candidateId || 'all');
    setVerificationError(null);
    setVerificationNotice(null);

    try {
      // Check if candidate is blocked due to contradictory inventory or lack of safe version
      const targetCandidate =
        candidateId && candidateId !== 'all'
          ? candidates.find(
              (c) =>
                c.candidate_id === candidateId ||
                c.package_name === candidateId ||
                c.target_component === candidateId
            )
          : null;

      if (
        targetCandidate &&
        (targetCandidate.strategy === 'NO_SAFE_CANDIDATE' ||
          targetCandidate.status === 'CONTRADICTION_BLOCKED' ||
          targetCandidate.status === 'NO_SAFE_CANDIDATE' ||
          (!targetCandidate.target_version && targetCandidate.strategy !== 'REMOVE_DEPENDENCY'))
      ) {
        setVerificationResponse(null);
        setVerificationNotice(
          `Automated verification is blocked for '${targetCandidate.package_name || targetCandidate.target_component || 'this component'}': contradictory inventory observations detected across manifests and lockfiles block automatic remediation. Manual review is required to resolve version discrepancies before an automated fix can be safely proven.`
        );
        return;
      }

      const res = await acsaApi.verifyRemediation(repositoryPath, candidateId, 'MODE_A_SIMULATED');

      // Task 2: Do not treat HTTP 200 with results: [] as successful verification
      if (!res.results || res.results.length === 0 || res.total_candidates_verified === 0) {
        setVerificationResponse(null);
        // Task 3: Display a clear, nontechnical UI message when no eligible remediation candidate can be verified
        const noticeMsg =
          res.warning ||
          res.summary ||
          (hasContradictions
            ? 'No eligible remediation candidate can be verified. Contradictory inventory observations detected across package manifests and lockfiles block automatic remediation until discrepancies are manually resolved.'
            : 'No eligible remediation candidates could be verified for this repository.');
        setVerificationNotice(noticeMsg);
      } else {
        setVerificationResponse(res);
        setVerificationNotice(null);
      }
    } catch (err: unknown) {
      setVerificationResponse(null);
      setVerificationError(
        err instanceof Error ? err.message : 'Failed to verify remediation candidate'
      );
    } finally {
      // Task 5: Always clear the loading state
      setVerifyingCandidateId(null);
    }
  };

  if (isLoading) {
    return (
      <LoadingState
        message="Calculating Minimum-Blast-Radius remediation candidates..."
        subtext="Evaluating dependency relations, advisory resolutions, and safe upgrade boundaries."
      />
    );
  }

  if (!remediationReport || candidates.length === 0) {
    return (
      <div>
        <div className="section-header">
          <h2 className="section-title">Minimum-Blast-Radius Remediation</h2>
          <p className="section-subtitle">
            Find the smallest defensible remediation that closes proven exposures while minimizing breaking changes.
          </p>
        </div>
        <EmptyState
          title="No remediation analysis executed"
          description="Run remediation analysis to calculate deterministic minimum-blast-radius candidates and patch simulations."
          actionLabel="Generate Remediation Candidates"
          onAction={onGenerateRemediation}
        />
      </div>
    );
  }

  return (
    <div>
      <div className="section-header">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <h2 className="section-title">Minimum-Blast-Radius Remediation</h2>
            <p className="section-subtitle">
              Generated {candidatesGenerated} candidate fix{candidatesGenerated === 1 ? '' : 'es'} across {totalFindingsEvaluated} evaluated findings
            </p>
          </div>
          <button
            type="button"
            className="btn btn-primary"
            onClick={() => handleVerify()}
            disabled={verifyingCandidateId !== null}
          >
            {verifyingCandidateId === 'all' ? 'Verifying...' : 'Verify All Candidates'}
          </button>
        </div>
      </div>

      {hasContradictions && (
        <div className="amber-banner">
          ⚠️ <strong>Contradictory Inventory Observations Detected:</strong> Automated in-place updates are blocked for affected components until manifest and lockfile discrepancies are resolved.
        </div>
      )}

      {requiresLockfileRegen && (
        <div className="amber-banner" style={{ background: 'var(--color-bg-base)', border: '1px solid var(--color-border-strong)' }}>
          ℹ️ <strong>Lockfile Notice:</strong> Applying candidates modifies dependency declarations. Complete closure will require lockfile regeneration.
        </div>
      )}

      {verificationError && (
        <div className="error-banner" role="alert" style={{ marginBottom: '1rem' }}>
          <strong>Verification Error:</strong> {verificationError}
        </div>
      )}

      {verificationNotice && (
        <div
          className="amber-banner"
          role="status"
          style={{ marginBottom: '1rem', borderLeft: '4px solid var(--color-warning, #d97706)' }}
        >
          <div style={{ display: 'flex', alignItems: 'flex-start', gap: '0.5rem' }}>
            <span style={{ fontSize: '1.2rem', lineHeight: 1 }}>⚠️</span>
            <div>
              <strong>Verification Blocked / No Eligible Candidates:</strong>
              <p style={{ margin: '0.25rem 0 0', fontSize: '0.9rem', lineHeight: 1.4 }}>
                {verificationNotice}
              </p>
            </div>
          </div>
        </div>
      )}

      {/* Candidates List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {candidates.map((cand) => {
          const isVerifying = verifyingCandidateId === cand.candidate_id;
          const isContradictionBlocked =
            cand.status === 'CONTRADICTION_BLOCKED' ||
            cand.strategy === 'NO_SAFE_CANDIDATE' ||
            cand.status === 'NO_SAFE_CANDIDATE' ||
            (hasContradictions && !cand.target_version && cand.strategy !== 'REMOVE_DEPENDENCY');

          return (
            <div key={cand.candidate_id} className="card">
              <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '0.75rem' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
                    <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                      {cand.package_name || cand.target_component}
                    </h3>
                    <span className="badge badge-gray">{cand.strategy}</span>
                    {isContradictionBlocked && (
                      <span className="badge badge-amber">Contradictory Inventory</span>
                    )}
                  </div>
                  <div style={{ fontSize: '0.9rem', color: 'var(--color-text-secondary)' }}>
                    Current Version: <strong style={{ color: 'var(--color-text-primary)' }}>{cand.current_version}</strong> → Target:{' '}
                    <strong style={{ color: cand.target_version ? 'var(--status-green-text)' : 'var(--status-amber-text)' }}>
                      {cand.target_version || cand.proposed_version || 'Manual Review Required'}
                    </strong>
                  </div>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <button
                    type="button"
                    className="btn btn-secondary btn-sm"
                    onClick={() => handleVerify(cand.candidate_id)}
                    disabled={verifyingCandidateId !== null}
                    title={isContradictionBlocked ? 'Automated verification is blocked by contradictory inventory' : undefined}
                  >
                    {isVerifying ? 'Verifying Proof...' : isContradictionBlocked ? 'Verify Remediation (Blocked)' : 'Verify Remediation'}
                  </button>
                </div>
              </div>

              {isContradictionBlocked && (
                <div
                  className="amber-banner"
                  style={{
                    margin: '0.5rem 0 0.75rem 0',
                    padding: '0.5rem 0.75rem',
                    fontSize: '0.825rem',
                    borderLeft: '3px solid var(--color-warning, #d97706)',
                  }}
                >
                  ⚠️ <strong>Automated Verification Blocked:</strong> Contradictory inventory observations detected across manifests and lockfiles prevent automated remediation. Manual review is required to resolve package version discrepancies.
                </div>
              )}

              {/* Deterministic Dimensions */}
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '0.75rem', padding: '0.75rem', background: 'var(--color-bg-subtle)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--color-border-subtle)', marginBottom: '0.75rem', fontSize: '0.825rem' }}>
                <div>
                  <span style={{ color: 'var(--color-text-tertiary)', fontSize: '0.725rem', fontWeight: 600 }}>RELEVANT ADVISORIES</span>
                  <div>
                    <strong>{cand.closed_advisories_count}</strong> / <strong>{cand.total_advisories_count}</strong> resolved
                  </div>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-tertiary)', fontSize: '0.725rem', fontWeight: 600 }}>CLOSURE STATUS</span>
                  <div><StatusBadge status={cand.closure_status} size="sm" /></div>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-tertiary)', fontSize: '0.725rem', fontWeight: 600 }}>EVIDENCE CONFIDENCE</span>
                  <div>
                    <span className={`badge ${cand.confidence_level === 'HIGH' ? 'badge-green' : cand.confidence_level === 'MEDIUM' ? 'badge-amber' : 'badge-gray'}`} style={{ fontSize: '0.725rem' }}>
                      {cand.confidence_level}
                    </span>
                  </div>
                </div>
                <div>
                  <span style={{ color: 'var(--color-text-tertiary)', fontSize: '0.725rem', fontWeight: 600 }}>FILES AFFECTED</span>
                  <div>{cand.files_changed && cand.files_changed.length > 0 ? cand.files_changed.join(', ') : 'package.json'}</div>
                </div>
              </div>

              {cand.reason && (
                <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)', marginBottom: '0.5rem' }}>
                  <strong>Rationale:</strong> {cand.reason}
                </p>
              )}

              {/* Simulated Unified Patch Preview */}
              {cand.simulated_patch && (
                <details style={{ marginTop: '0.5rem', fontSize: '0.8rem' }}>
                  <summary style={{ cursor: 'pointer', fontWeight: 600, color: 'var(--color-text-secondary)' }}>
                    View Non-Destructive Simulated Patch
                  </summary>
                  <pre className="code-block" style={{ marginTop: '0.35rem' }}>
                    {cand.simulated_patch}
                  </pre>
                </details>
              )}
            </div>
          );
        })}
      </div>

      {/* Proof-Carrying Remediation Verification Results */}
      {verificationResponse && verificationResponse.results.length > 0 && (
        <div style={{ marginTop: '2rem' }}>
          <div className="section-header">
            <h3 className="section-title">Proof-Carrying Verification Results</h3>
            <p className="section-subtitle">
              Mode: <code className="code-pill">{verificationResponse.verification_mode}</code> • Verified {verificationResponse.total_candidates_verified} candidate{verificationResponse.total_candidates_verified === 1 ? '' : 's'}
            </p>
          </div>

          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
            <span className="badge badge-green">Proven Remediated: {verificationResponse.proven_remediated_count}</span>
            <span className="badge badge-amber">Requires Verification: {verificationResponse.requires_verification_count}</span>
            <span className="badge badge-red">Failed: {verificationResponse.failed_count}</span>
          </div>

          {verificationResponse.results.map((item, idx) => (
            <ProofConditionsTable key={idx} item={item} />
          ))}
        </div>
      )}
    </div>
  );
};
