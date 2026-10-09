import React from 'react';
import type { Finding, RemediationCandidate } from '../types/api';
import { VerdictBadge } from '../components/VerdictBadge';
import { ExposurePath } from '../components/ExposurePath';
import { EvidenceProvenanceSection } from '../components/EvidenceProvenanceSection';

interface FindingDetailViewProps {
  finding: Finding;
  remediationCandidate?: RemediationCandidate | null;
  onBack: () => void;
  onViewRemediation: (candidate?: RemediationCandidate | null) => void;
  onViewProbes: (findingId: string) => void;
}

export const FindingDetailView: React.FC<FindingDetailViewProps> = ({
  finding,
  remediationCandidate,
  onBack,
  onViewRemediation,
  onViewProbes,
}) => {
  const { component, vulnerability, verdict, reachability, context, notes } = finding;

  // Generate concise evidence-based explanation for "WHY IT MATTERS"
  const generateWhyItMatters = () => {
    const compName = component?.name || 'Package';
    const compVer = component?.version || 'Unresolved';
    const vulnId = vulnerability?.id || 'Advisory';

    if (verdict === 'PROVEN_EXPOSURE') {
      const entry = context?.entry_point || reachability?.entry_point || 'an application HTTP route';
      const input = context?.source?.expression || 'external request parameters';
      const symbol = reachability?.target_symbol || 'the vulnerable routine';
      return `Proven security exposure: External input from ${input} entering through ${entry} traverses the application call graph to invoke ${symbol} within ${compName}@${compVer}. This represents an active, reachable security flaw.`;
    }
    if (verdict === 'PROVEN_AFFECTED') {
      const symDesc = reachability?.target_symbol ? `vulnerable symbol '${reachability.target_symbol}'` : 'vulnerable routines';
      const reachText = reachability?.status === 'NOT_REACHABLE'
        ? ` However, ${symDesc} is proven not reachable in application source code.`
        : '';
      return `Component ${compName}@${compVer} installed version is confirmed affected by advisory ${vulnId}.${reachText} Package applicability alone confirms the installed library version, while application exposure remains a separate conclusion. Exploitability is not implied from component applicability alone.`;
    }
    if (verdict === 'POTENTIALLY_AFFECTED') {
      return `Component ${compName}@${compVer} is declared in dependency manifests and affected by ${vulnId}. Reachability could not be conclusively proven due to unresolved dynamic boundaries.`;
    }
    if (verdict === 'UNKNOWN') {
      return `Analysis is inconclusive. Dynamic JavaScript language features or missing symbol signatures prevented static verification. UNKNOWN must never be treated as safe.`;
    }
    if (verdict === 'CONTRADICTORY') {
      return `Conflicting inventory signals detected across package manifest, lockfile, and SBOM observations for ${compName}. Ground truth cannot be established without reconciling inventory artifacts.`;
    }
    if (verdict === 'PROVEN_NOT_AFFECTED') {
      return `Verified safe: Static AST and call graph analysis confirm ${compName}@${compVer} is not invoked by any application execution paths, or the installed version is outside vulnerable advisory bounds.`;
    }
    return notes || vulnerability?.summary || 'Security finding evaluated by ACSA supply chain engine.';
  };

  return (
    <div>
      <div style={{ marginBottom: '1rem' }}>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={onBack}
        >
          ← Back to Findings
        </button>
      </div>

      {/* Header Banner */}
      <div className="card" style={{ borderLeft: verdict === 'PROVEN_EXPOSURE' ? '4px solid var(--status-red-text)' : verdict === 'UNKNOWN' ? '4px solid var(--status-amber-text)' : '4px solid var(--status-green-text)' }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.35rem' }}>
              <span style={{ fontSize: '1.25rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
                {component?.name || 'Unknown Component'}
              </span>
              <span style={{ fontFamily: 'var(--font-mono)', fontSize: '0.9rem', color: 'var(--color-text-secondary)' }}>
                {vulnerability?.id || 'Unknown Advisory'}
              </span>
            </div>
            <div style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)' }}>
              Installed Version: <strong style={{ color: 'var(--color-text-primary)' }}>{component?.version || 'Unresolved'}</strong>
              {component?.is_direct !== undefined && (
                <span style={{ marginLeft: '0.75rem' }}>
                  ({component.is_direct ? 'Direct manifest dependency' : 'Transitive dependency'})
                </span>
              )}
            </div>
          </div>
          <div>
            <VerdictBadge verdict={verdict} />
          </div>
        </div>

        {vulnerability?.summary && (
          <p style={{ marginTop: '0.75rem', fontSize: '0.875rem', color: 'var(--color-text-primary)', borderTop: '1px solid var(--color-border-subtle)', paddingTop: '0.75rem' }}>
            {vulnerability.summary}
          </p>
        )}
      </div>

      {/* WHY IT MATTERS */}
      <div className="card">
        <h3 className="card-title">Why It Matters</h3>
        <p style={{ fontSize: '0.875rem', color: 'var(--color-text-primary)', lineHeight: 1.6 }}>
          {generateWhyItMatters()}
        </p>
      </div>

      {/* UNKNOWN EXPERIENCE (First-Class Security State) */}
      {verdict === 'UNKNOWN' && (
        <div className="card" style={{ background: 'var(--status-amber-bg)', borderColor: 'var(--status-amber-border)' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
            <span style={{ fontSize: '1.1rem' }}>🟡</span>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--status-amber-text)' }}>
              UNKNOWN — First-Class Security State
            </h3>
          </div>
          <p style={{ fontSize: '0.875rem', color: 'var(--color-text-primary)', marginBottom: '0.75rem' }}>
            ACSA cannot currently prove whether this finding is reachable or safe. In sound security engineering, UNKNOWN must never be assumed benign.
          </p>

          <div style={{ background: 'var(--color-bg-base)', padding: '0.85rem', borderRadius: 'var(--radius-sm)', border: '1px solid var(--status-amber-border)', marginBottom: '0.75rem' }}>
            <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--status-amber-text)', textTransform: 'uppercase' }}>
              Why Analysis is Inconclusive:
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--color-text-primary)', marginTop: '0.25rem' }}>
              {finding.uncertainty_reason || reachability?.uncertainty_reason || 'Dynamic code constructs or dynamic routing registration prevented static AST dispatch verification.'}
            </p>

            <div style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--status-amber-text)', textTransform: 'uppercase', marginTop: '0.65rem' }}>
              Missing Evidence Needed to Resolve Uncertainty:
            </div>
            <p style={{ fontSize: '0.85rem', color: 'var(--color-text-primary)', marginTop: '0.25rem' }}>
              {finding.missing_evidence || reachability?.missing_evidence || 'Runtime observation showing whether application HTTP dispatch reaches the target component.'}
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>
              A targeted dynamic probe specification is available to resolve this uncertainty without running untrusted code.
            </span>
            <button
              type="button"
              className="btn btn-primary btn-sm"
              onClick={() => onViewProbes(finding.id)}
            >
              View Targeted Probe Specification →
            </button>
          </div>
        </div>
      )}

      {/* EXPOSURE PATH (Only rendered from actual evidence) */}
      <div className="card">
        <h3 className="card-title">Exposure Path</h3>
        <ExposurePath finding={finding} />
      </div>

      {/* EXPANDABLE EVIDENCE SECTIONS */}
      <div className="card">
        <EvidenceProvenanceSection finding={finding} />
      </div>

      {/* RECOMMENDED REMEDIATION SUMMARY */}
      <div className="card">
        <h3 className="card-title">Recommended Remediation</h3>
        {remediationCandidate ? (
          <div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '0.75rem', fontSize: '0.85rem', marginBottom: '0.75rem' }}>
              <div>
                <span style={{ color: 'var(--color-text-tertiary)', fontSize: '0.75rem' }}>UPGRADE TARGET:</span>
                <div>
                  <strong>{remediationCandidate.package_name || remediationCandidate.target_component || 'Target Component'}</strong>{' '}
                  {remediationCandidate.current_version} →{' '}
                  <strong style={{ color: 'var(--status-green-text)' }}>
                    {remediationCandidate.target_version || remediationCandidate.proposed_version || 'Manual review required'}
                  </strong>
                </div>
              </div>
              <div>
                <span style={{ color: 'var(--color-text-tertiary)', fontSize: '0.75rem' }}>STRATEGY:</span>
                <div><code>{remediationCandidate.strategy}</code></div>
              </div>
              <div>
                <span style={{ color: 'var(--color-text-tertiary)', fontSize: '0.75rem' }}>CLOSURE STATUS:</span>
                <div>
                  <span className={`badge ${remediationCandidate.closure_status === 'PROVEN_CLOSED' ? 'badge-green' : 'badge-amber'}`}>
                    {remediationCandidate.closure_status}
                  </span>
                </div>
              </div>
              <div>
                <span style={{ color: 'var(--color-text-tertiary)', fontSize: '0.75rem' }}>EVIDENCE CONFIDENCE:</span>
                <div>
                  <span className={`badge ${remediationCandidate.confidence_level === 'HIGH' ? 'badge-green' : remediationCandidate.confidence_level === 'MEDIUM' ? 'badge-amber' : 'badge-gray'}`}>
                    {remediationCandidate.confidence_level || 'LOW'}
                  </span>
                </div>
              </div>
            </div>

            <p style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', marginBottom: '0.75rem' }}>
              {remediationCandidate.reason}
            </p>

            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => onViewRemediation(remediationCandidate)}
            >
              Inspect Remediation & Proof Verification →
            </button>
          </div>
        ) : (
          <p style={{ fontSize: '0.85rem', color: 'var(--color-text-secondary)' }}>
            No specific Minimum-Blast-Radius candidate generated for this finding yet. Run remediation analysis to evaluate candidate fixes.
          </p>
        )}
      </div>
    </div>
  );
};
