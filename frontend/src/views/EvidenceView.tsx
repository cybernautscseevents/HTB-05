import React, { useState } from 'react';
import type { Evidence, VulnerabilityScanResult } from '../types/api';
import { EmptyState } from '../components/EmptyState';

interface EvidenceViewProps {
  scanResult: VulnerabilityScanResult | null;
  onScan: () => void;
}

export const EvidenceView: React.FC<EvidenceViewProps> = ({
  scanResult,
  onScan,
}) => {
  const [selectedEvidence, setSelectedEvidence] = useState<Evidence | null>(null);
  const [filterType, setFilterType] = useState<string>('ALL');

  if (!scanResult) {
    return (
      <EmptyState
        title="No evidence records available"
        description="Run a repository analysis to generate verifiable evidence graph records."
        actionLabel="Scan Repository"
        onAction={onScan}
      />
    );
  }

  const { evidence, findings } = scanResult;

  // Filter evidence
  const filteredEvidence = evidence.filter((ev) => {
    if (filterType !== 'ALL' && ev.evidence_type !== filterType) {
      return false;
    }
    return true;
  });

  const uniqueEvidenceTypes = Array.from(new Set(evidence.map((e) => e.evidence_type)));

  // Identify sample evidence chain from a top exposed or evaluated finding
  const topFinding = findings.find((f) => f.verdict === 'PROVEN_EXPOSURE') || findings[0];

  return (
    <div>
      <div className="section-header">
        <h2 className="section-title">Evidence & Provenance Graph</h2>
        <p className="section-subtitle">
          {evidence.length} machine-verifiable evidence nodes supporting security verdicts for <code className="code-pill">{scanResult.repository_path}</code>
        </p>
      </div>

      {/* Simplified High-Level Provenance Chain */}
      {topFinding && (
        <div className="card" style={{ marginBottom: '1.5rem' }}>
          <h3 className="card-title">Canonical Evidence Chain: {topFinding.component?.name || 'Component'}</h3>
          <p style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', marginBottom: '0.75rem' }}>
            Linear evidence flow linking repository artifacts to authoritative verdicts:
          </p>

          <div className="exposure-path-container" style={{ margin: 0 }}>
            <div className="exposure-step-list">
              <div className="exposure-step">
                <span className="exposure-step-indicator">ARTIFACT</span>
                <div className="exposure-step-content">
                  <div className="exposure-step-title">{topFinding.source_artifact_path || 'package-lock.json / package.json'}</div>
                  <div className="exposure-step-detail">Phase 1 Real Repository Ingestion</div>
                </div>
              </div>
              <div className="step-arrow" aria-hidden="true">↓</div>

              <div className="exposure-step">
                <span className="exposure-step-indicator">COMPONENT</span>
                <div className="exposure-step-content">
                  <div className="exposure-step-title">{topFinding.component?.name || 'Component'}</div>
                  <div className="exposure-step-detail">Resolved Canonical Inventory</div>
                </div>
              </div>
              <div className="step-arrow" aria-hidden="true">↓</div>

              <div className="exposure-step">
                <span className="exposure-step-indicator">VERSION</span>
                <div className="exposure-step-content">
                  <div className="exposure-step-title">{topFinding.component?.version || 'Unresolved'}</div>
                  <div className="exposure-step-detail">Contradiction-Aware Version Evaluation</div>
                </div>
              </div>
              <div className="step-arrow" aria-hidden="true">↓</div>

              <div className="exposure-step">
                <span className="exposure-step-indicator">ADVISORY</span>
                <div className="exposure-step-content">
                  <div className="exposure-step-title">{topFinding.vulnerability?.id || 'Unknown Advisory'}</div>
                  <div className="exposure-step-detail">OSV Live Vulnerability Intelligence</div>
                </div>
              </div>
              <div className="step-arrow" aria-hidden="true">↓</div>

              <div className="exposure-step">
                <span className="exposure-step-indicator">SYMBOL</span>
                <div className="exposure-step-content">
                  <div className="exposure-step-title">
                    {topFinding.vulnerability?.vulnerable_symbols && topFinding.vulnerability.vulnerable_symbols.length > 0
                      ? topFinding.vulnerability.vulnerable_symbols.join(', ')
                      : 'Package Scope'}
                  </div>
                  <div className="exposure-step-detail">Vulnerable API Surface</div>
                </div>
              </div>
              <div className="step-arrow" aria-hidden="true">↓</div>

              <div className="exposure-step">
                <span className="exposure-step-indicator">ENTRY POINT</span>
                <div className="exposure-step-content">
                  <div className="exposure-step-title">{topFinding.reachability?.entry_point || 'Not established'}</div>
                  <div className="exposure-step-detail">Phase 3 Static AST Reachability</div>
                </div>
              </div>
              <div className="step-arrow" aria-hidden="true">↓</div>

              <div className="exposure-step">
                <span className="exposure-step-indicator">ATTACKER INPUT</span>
                <div className="exposure-step-content">
                  <div className="exposure-step-title">{topFinding.context?.source?.expression || 'Not established'}</div>
                  <div className="exposure-step-detail">Phase 4 Attacker Control Determination</div>
                </div>
              </div>
              <div className="step-arrow" aria-hidden="true">↓</div>

              <div className="exposure-step">
                <span className="exposure-step-indicator">VERDICT</span>
                <div className="exposure-step-content">
                  <div className="exposure-step-title">{topFinding.verdict}</div>
                  <div className="exposure-step-detail">Multi-Source Deterministic Evidence Fusion</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Real Evidence Graph Records Table */}
      <div className="card">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '0.75rem' }}>
          <div>
            <h3 className="card-title" style={{ marginBottom: 0 }}>Verifiable Evidence Records</h3>
            <span style={{ fontSize: '0.8rem', color: 'var(--color-text-tertiary)' }}>
              Provenance telemetry records generated across ingestion, intelligence, reachability, and fusion
            </span>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <label htmlFor="evidence-type-filter" style={{ fontSize: '0.775rem', fontWeight: 600, color: 'var(--color-text-secondary)' }}>
              Type:
            </label>
            <select
              id="evidence-type-filter"
              className="repo-input"
              style={{ padding: '0.35rem 0.5rem', fontSize: '0.8rem' }}
              value={filterType}
              onChange={(e) => setFilterType(e.target.value)}
            >
              <option value="ALL">All Types ({evidence.length})</option>
              {uniqueEvidenceTypes.map((t) => (
                <option key={t} value={t}>{t}</option>
              ))}
            </select>
          </div>
        </div>

        <div className="table-container">
          <table className="data-table">
            <thead>
              <tr>
                <th>ID</th>
                <th>Type</th>
                <th>Source</th>
                <th>Description</th>
                <th>Confidence</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {filteredEvidence.slice(0, 50).map((ev) => (
                <tr
                  key={ev.id}
                  className="clickable"
                  onClick={() => setSelectedEvidence(ev)}
                >
                  <td>
                    <code className="code-pill">{ev.id ? ev.id.slice(0, 8) : 'unknown'}</code>
                  </td>
                  <td>
                    <span className="badge badge-gray">{ev.evidence_type}</span>
                  </td>
                  <td>
                    <span style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)' }}>{ev.source}</span>
                  </td>
                  <td>
                    <span style={{ fontSize: '0.825rem' }}>{ev.description}</span>
                  </td>
                  <td>
                    <span style={{ fontWeight: 600 }}>
                      {typeof ev.confidence === 'number' ? `${(ev.confidence * 100).toFixed(0)}%` : 'Not established'}
                    </span>
                  </td>
                  <td>
                    <button
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={(e) => {
                        e.stopPropagation();
                        setSelectedEvidence(ev);
                      }}
                    >
                      Raw JSON
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Raw Evidence Inspector Modal/Card */}
      {selectedEvidence && (
        <div className="card" style={{ marginTop: '1rem', borderLeft: '4px solid var(--action-primary-bg)' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.5rem' }}>
            <h4 style={{ fontSize: '1rem', fontWeight: 700 }}>
              Evidence Provenance Record: <code className="code-pill">{selectedEvidence.id}</code>
            </h4>
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => setSelectedEvidence(null)}
            >
              Close
            </button>
          </div>
          <pre className="code-block" style={{ maxHeight: '350px', overflowY: 'auto' }}>
            {JSON.stringify(selectedEvidence, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
};
