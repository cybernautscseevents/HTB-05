import React from 'react';
import type { Finding, VulnerabilityScanResult } from '../types/api';
import { VerdictBadge } from '../components/VerdictBadge';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState } from '../components/EmptyState';

interface OverviewViewProps {
  scanResult: VulnerabilityScanResult | null;
  onSelectFinding: (finding: Finding) => void;
  onViewAllFindings: () => void;
  onScan: () => void;
  onNavigateToRemediation: () => void;
}

export const OverviewView: React.FC<OverviewViewProps> = ({
  scanResult,
  onSelectFinding,
  onViewAllFindings,
  onScan,
  onNavigateToRemediation,
}) => {
  if (!scanResult) {
    return (
      <EmptyState
        title="No repository analyzed yet"
        description="Run an analysis against a target workspace to generate evidence-backed security findings."
        actionLabel="Scan NodeGoat Fixture"
        onAction={onScan}
      />
    );
  }

  // Derive attention values strictly from real scanResult data
  const attentionCount = scanResult.proven_exposure_count + scanResult.potentially_affected_count + scanResult.unknown_count + scanResult.contradictory_count;
  const confirmedExposureCount = scanResult.proven_exposure_count;
  const unknownCount = scanResult.unknown_count;
  const verifiedSafeCount = scanResult.proven_not_affected_count;

  // Recent/top findings: prioritize PROVEN_EXPOSURE, then UNKNOWN, then others
  const sortedFindings = [...scanResult.findings].sort((a, b) => {
    const score = (f: Finding) => {
      if (f.verdict === 'PROVEN_EXPOSURE') return 100;
      if (f.verdict === 'PROVEN_AFFECTED') return 80;
      if (f.verdict === 'POTENTIALLY_AFFECTED') return 60;
      if (f.verdict === 'UNKNOWN') return 50;
      if (f.verdict === 'CONTRADICTORY') return 40;
      return 10;
    };
    return score(b) - score(a);
  });
  const recentFindings = sortedFindings.slice(0, 5);

  return (
    <div>
      <div className="section-header">
        <h2 className="section-title">Overview</h2>
        <p className="section-subtitle">
          Supply-chain security posture for <code className="code-pill">{scanResult.repository_path}</code>
        </p>
      </div>

      {/* ATTENTION METRICS */}
      <div className="attention-grid">
        <div className="attention-card red">
          <div className="attention-label">Confirmed Exposure</div>
          <div className="attention-value">{confirmedExposureCount}</div>
          <div className="attention-desc">Proven reachable vulnerable components</div>
        </div>

        <div className="attention-card amber">
          <div className="attention-label">Unknown / Needs Evidence</div>
          <div className="attention-value">{unknownCount}</div>
          <div className="attention-desc">Dynamic dispatch requires targeted probe</div>
        </div>

        <div className="attention-card gray">
          <div className="attention-label">Requires Attention</div>
          <div className="attention-value">{attentionCount}</div>
          <div className="attention-desc">Total actionable non-safe findings</div>
        </div>

        <div className="attention-card green">
          <div className="attention-label">Verified Safe</div>
          <div className="attention-value">{verifiedSafeCount}</div>
          <div className="attention-desc">Proven not affected by known advisories</div>
        </div>
      </div>

      {/* REPOSITORY STATUS */}
      <div className="card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.75rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <h3 className="card-title" style={{ marginBottom: 0 }}>Repository Pipeline Status</h3>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onNavigateToRemediation}
          >
            Inspect Remediation Candidates →
          </button>
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '0.75rem', fontSize: '0.85rem' }}>
          <div>
            <div style={{ color: 'var(--color-text-tertiary)', fontSize: '0.75rem', fontWeight: 600 }}>CANONICAL INVENTORY</div>
            <div style={{ marginTop: '0.2rem' }}>
              <strong>{Object.keys(scanResult.inventory?.components || {}).length}</strong> components
              {scanResult.inventory?.is_contradictory ? (
                <span style={{ color: 'var(--status-amber-text)', marginLeft: '0.35rem' }}>(Contradictory)</span>
              ) : (
                <span style={{ color: 'var(--status-green-text)', marginLeft: '0.35rem' }}>(Consistent)</span>
              )}
            </div>
          </div>
          <div>
            <div style={{ color: 'var(--color-text-tertiary)', fontSize: '0.75rem', fontWeight: 600 }}>OSV INTELLIGENCE</div>
            <div style={{ marginTop: '0.2rem' }}>
              <strong>{scanResult.advisories_count}</strong> advisories evaluated ({scanResult.from_cache_count} cached)
            </div>
          </div>
          <div>
            <div style={{ color: 'var(--color-text-tertiary)', fontSize: '0.75rem', fontWeight: 600 }}>STATIC REACHABILITY</div>
            <div style={{ marginTop: '0.2rem' }}>
              {scanResult.reachability_evaluated ? (
                <span style={{ color: 'var(--status-green-text)', fontWeight: 600 }}>✓ Evaluated AST</span>
              ) : (
                <span style={{ color: 'var(--color-text-tertiary)' }}>Pending</span>
              )}
            </div>
          </div>
          <div>
            <div style={{ color: 'var(--color-text-tertiary)', fontSize: '0.75rem', fontWeight: 600 }}>EVIDENCE FUSION</div>
            <div style={{ marginTop: '0.2rem' }}>
              <strong>{scanResult.evidence.length}</strong> evidence nodes fused
            </div>
          </div>
        </div>
      </div>

      {/* RECENT FINDINGS */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.85rem' }}>
          <div>
            <h3 className="card-title" style={{ marginBottom: 0 }}>High Priority Findings</h3>
            <span style={{ fontSize: '0.8rem', color: 'var(--color-text-tertiary)' }}>
              Top findings requiring security triage
            </span>
          </div>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onViewAllFindings}
          >
            View all {scanResult.findings.length} findings →
          </button>
        </div>

        {recentFindings.length === 0 ? (
          <p style={{ color: 'var(--color-text-secondary)', fontSize: '0.875rem' }}>No findings discovered in repository.</p>
        ) : (
          <div className="table-container">
            <table className="data-table">
              <thead>
                <tr>
                  <th>Component</th>
                  <th>Version</th>
                  <th>Advisory</th>
                  <th>Verdict</th>
                  <th>Reachability</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody>
                {recentFindings.map((finding) => (
                  <tr
                    key={finding.id}
                    className="clickable"
                    onClick={() => onSelectFinding(finding)}
                  >
                    <td>
                      <strong>{finding.component?.name || 'Unknown'}</strong>
                    </td>
                    <td>
                      <code className="code-pill">{finding.component?.version || 'unknown'}</code>
                    </td>
                    <td>
                      <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                        {finding.vulnerability?.id || 'Unknown Advisory'}
                      </span>
                    </td>
                    <td>
                      <VerdictBadge verdict={finding.verdict} size="sm" />
                    </td>
                    <td>
                      <StatusBadge
                        status={finding.reachability ? finding.reachability.status : 'UNKNOWN'}
                        size="sm"
                      />
                    </td>
                    <td>
                      <button
                        type="button"
                        className="btn btn-secondary btn-sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          onSelectFinding(finding);
                        }}
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
