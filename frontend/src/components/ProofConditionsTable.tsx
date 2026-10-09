import React from 'react';
import type { ProofVerificationItem } from '../types/api';
import { VerdictBadge } from './VerdictBadge';
import { StatusBadge } from './StatusBadge';

interface ProofConditionsTableProps {
  item: ProofVerificationItem;
}

export const ProofConditionsTable: React.FC<ProofConditionsTableProps> = ({ item }) => {
  const { before, after, proof_conditions, verification_status, final_verdict } = item;

  return (
    <div className="card" style={{ marginTop: '1rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '1rem' }}>
        <div>
          <h4 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
            Proof-Carrying Verification: <code className="code-pill">{item.target_component}</code>
          </h4>
          <span style={{ fontSize: '0.8rem', color: 'var(--color-text-tertiary)' }}>
            Strategy: {item.strategy} • Candidate ID: {item.candidate ? item.candidate.slice(0, 8) : 'Unknown'}...
          </span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <span style={{ fontSize: '0.825rem', fontWeight: 600, color: 'var(--color-text-secondary)' }}>Verification Status:</span>
          <StatusBadge status={verification_status} />
        </div>
      </div>

      {/* Before vs After Snapshots */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', marginBottom: '1.25rem' }}>
        <div style={{ background: 'var(--color-bg-subtle)', border: '1px solid var(--color-border-base)', borderRadius: 'var(--radius-sm)', padding: '0.85rem' }}>
          <div style={{ fontSize: '0.775rem', fontWeight: 700, color: 'var(--status-red-text)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
            BEFORE REMEDIATION
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.825rem' }}>
            <div>Version: <strong>{before.version || 'Unresolved'}</strong></div>
            <div>Advisories: <strong>{before.advisories && before.advisories.length > 0 ? before.advisories.join(', ') : 'None'}</strong></div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              Verdict: <VerdictBadge verdict={before.verdict} size="sm" />
            </div>
            <div>Reachability: <StatusBadge status={before.reachability_status} size="sm" /></div>
            <div>Exposure Paths: <strong>{before.exposure_paths ? before.exposure_paths.length : 0}</strong></div>
          </div>
        </div>

        <div style={{ background: 'var(--color-bg-subtle)', border: '1px solid var(--color-border-base)', borderRadius: 'var(--radius-sm)', padding: '0.85rem' }}>
          <div style={{ fontSize: '0.775rem', fontWeight: 700, color: 'var(--status-green-text)', textTransform: 'uppercase', marginBottom: '0.5rem' }}>
            AFTER REMEDIATION
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem', fontSize: '0.825rem' }}>
            <div>Version: <strong>{after.version || 'Unresolved'}</strong></div>
            <div>Advisories: <strong>{after.advisories && after.advisories.length > 0 ? after.advisories.join(', ') : '0 (Resolved)'}</strong></div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              Verdict: <VerdictBadge verdict={after.verdict} size="sm" />
            </div>
            <div>Reachability: <StatusBadge status={after.reachability_status} size="sm" /></div>
            <div>Exposure Paths: <strong>{after.exposure_paths ? after.exposure_paths.length : 0}</strong></div>
          </div>
        </div>
      </div>

      {/* Machine-Verifiable Proof Conditions Table */}
      <h5 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--color-text-secondary)', marginBottom: '0.5rem' }}>
        Machine-Verifiable Proof Conditions
      </h5>
      <table className="proof-table">
        <thead>
          <tr>
            <th>Condition</th>
            <th>Evaluated Evidence</th>
            <th>Closure State</th>
          </tr>
        </thead>
        <tbody>
          <tr>
            <td><strong>Version Closure</strong></td>
            <td>Verified AFTER version is outside all known vulnerable ranges</td>
            <td>
              {proof_conditions.version_closed ? (
                <span style={{ color: 'var(--status-green-text)', fontWeight: 600 }}>✓ CLOSED</span>
              ) : (
                <span style={{ color: 'var(--status-amber-text)', fontWeight: 600 }}>⚠️ UNVERIFIED</span>
              )}
            </td>
          </tr>
          <tr>
            <td><strong>Advisory Closure</strong></td>
            <td>All relevant advisories for target component resolved</td>
            <td>
              {proof_conditions.advisories_closed ? (
                <span style={{ color: 'var(--status-green-text)', fontWeight: 600 }}>✓ CLOSED</span>
              ) : (
                <span style={{ color: 'var(--status-amber-text)', fontWeight: 600 }}>⚠️ UNVERIFIED</span>
              )}
            </td>
          </tr>
          <tr>
            <td><strong>Vulnerable Symbol</strong></td>
            <td>Vulnerable function or method eliminated from call graph</td>
            <td>
              {proof_conditions.vulnerable_symbol_closed ? (
                <span style={{ color: 'var(--status-green-text)', fontWeight: 600 }}>✓ CLOSED</span>
              ) : (
                <span style={{ color: 'var(--status-amber-text)', fontWeight: 600 }}>⚠️ UNVERIFIED</span>
              )}
            </td>
          </tr>
          <tr>
            <td><strong>Exposure Path</strong></td>
            <td>Attacker-to-sink data flow path severed in evidence graph</td>
            <td>
              {proof_conditions.exposure_path_closed ? (
                <span style={{ color: 'var(--status-green-text)', fontWeight: 600 }}>✓ CLOSED</span>
              ) : (
                <span style={{ color: 'var(--status-amber-text)', fontWeight: 600 }}>⚠️ UNVERIFIED</span>
              )}
            </td>
          </tr>
          <tr>
            <td><strong>Test Validation</strong></td>
            <td>
              Outcome: <strong>{proof_conditions.test_status}</strong>
              {proof_conditions.test_reason && (
                <div style={{ fontSize: '0.75rem', color: 'var(--color-text-tertiary)' }}>
                  {proof_conditions.test_reason}
                </div>
              )}
            </td>
            <td>
              {proof_conditions.test_status === 'PASSED' ? (
                <span style={{ color: 'var(--status-green-text)', fontWeight: 600 }}>✓ PASSED</span>
              ) : proof_conditions.test_status === 'FAILED' ? (
                <span style={{ color: 'var(--status-red-text)', fontWeight: 600 }}>✕ FAILED</span>
              ) : (
                <span style={{ color: 'var(--color-text-tertiary)', fontWeight: 500 }}>— NOT EXECUTED</span>
              )}
            </td>
          </tr>
        </tbody>
      </table>

      {/* Uncertainty or Missing Evidence */}
      {(item.uncertainty_reason || item.missing_evidence) && (
        <div className="amber-banner" style={{ marginTop: '0.75rem' }}>
          {item.uncertainty_reason && (
            <div>
              <strong>Uncertainty Reason:</strong> {item.uncertainty_reason}
            </div>
          )}
          {item.missing_evidence && (
            <div style={{ marginTop: item.uncertainty_reason ? '0.35rem' : 0 }}>
              <strong>Missing Evidence:</strong> {item.missing_evidence}
            </div>
          )}
        </div>
      )}

      {/* Supporting Evidence Chain */}
      {item.evidence && item.evidence.length > 0 && (
        <div style={{ marginTop: '0.75rem', fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>
          <strong>Supporting Evidence Chain:</strong>{' '}
          {item.evidence.map((evId, idx) => (
            <code key={idx} className="code-pill" style={{ marginRight: '0.25rem' }}>
              {evId}
            </code>
          ))}
        </div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', borderTop: '1px solid var(--color-border-subtle)', paddingTop: '0.75rem', marginTop: '0.75rem' }}>
        <span style={{ fontSize: '0.825rem', color: 'var(--color-text-secondary)' }}>
          Authoritative Post-Verification Verdict:
        </span>
        <VerdictBadge verdict={final_verdict} />
      </div>
    </div>
  );
};
