import React, { useState } from 'react';
import type { Finding } from '../types/api';

interface EvidenceProvenanceSectionProps {
  finding: Finding;
}

export const EvidenceProvenanceSection: React.FC<EvidenceProvenanceSectionProps> = ({ finding }) => {
  const [openSections, setOpenSections] = useState<Record<string, boolean>>({
    inventory: true,
    intelligence: true,
    reachability: true,
    context: true,
    verdict: true,
  });

  const toggleSection = (key: string) => {
    setOpenSections((prev) => ({ ...prev, [key]: !prev[key] }));
  };

  const { component, vulnerability, reachability, context, verdict, notes } = finding;

  return (
    <div style={{ marginTop: '1.25rem' }}>
      <h4 style={{ fontSize: '0.95rem', fontWeight: 600, marginBottom: '0.75rem', color: 'var(--color-text-primary)' }}>
        Evidence & Provenance Verification
      </h4>

      {/* 1. Inventory */}
      <div className="accordion-item">
        <button
          type="button"
          className="accordion-header"
          onClick={() => toggleSection('inventory')}
          aria-expanded={openSections.inventory}
        >
          <span>1. Repository Inventory Observation</span>
          <span>{openSections.inventory ? '▲' : '▼'}</span>
        </button>
        {openSections.inventory && (
          <div className="accordion-body">
            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
              <li style={{ color: 'var(--status-green-text)', fontWeight: 500 }}>
                ✓ Exact installed version: <strong style={{ color: 'var(--color-text-primary)' }}>{component.version || 'Unknown'}</strong>
              </li>
              {finding.source_artifact_path && (
                <li style={{ color: 'var(--status-green-text)', fontWeight: 500 }}>
                  ✓ Originating manifest artifact: <code className="code-pill">{finding.source_artifact_path}</code>
                </li>
              )}
              {component.is_direct !== undefined && (
                <li style={{ color: 'var(--color-text-secondary)' }}>
                  • Dependency depth: {component.is_direct ? 'Direct manifest dependency' : 'Transitive dependency'}
                </li>
              )}
            </ul>
          </div>
        )}
      </div>

      {/* 2. Vulnerability Intelligence */}
      <div className="accordion-item">
        <button
          type="button"
          className="accordion-header"
          onClick={() => toggleSection('intelligence')}
          aria-expanded={openSections.intelligence}
        >
          <span>2. Vulnerability Intelligence (OSV / GHSA)</span>
          <span>{openSections.intelligence ? '▲' : '▼'}</span>
        </button>
        {openSections.intelligence && (
          <div className="accordion-body">
            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
              <li style={{ color: 'var(--status-green-text)', fontWeight: 500 }}>
                ✓ OSV Advisory match: <strong style={{ color: 'var(--color-text-primary)' }}>{vulnerability?.id || 'Unknown Advisory'}</strong>
              </li>
              {vulnerability?.aliases && vulnerability.aliases.length > 0 && (
                <li style={{ color: 'var(--color-text-secondary)' }}>
                  • Canonical aliases: {vulnerability.aliases.join(', ')}
                </li>
              )}
              <li style={{ color: 'var(--status-green-text)', fontWeight: 500 }}>
                ✓ Applicability Status: <strong style={{ color: 'var(--color-text-primary)' }}>{finding.applicability_status}</strong>
              </li>
              {vulnerability?.vulnerable_symbols && vulnerability.vulnerable_symbols.length > 0 && (
                <li style={{ color: 'var(--status-green-text)', fontWeight: 500 }}>
                  ✓ Vulnerable symbol identified: <code className="code-pill">{vulnerability.vulnerable_symbols.join(', ')}</code>
                </li>
              )}
              {vulnerability?.fixed_versions && vulnerability.fixed_versions.length > 0 && (
                <li style={{ color: 'var(--color-text-secondary)' }}>
                  • Upstream fixed versions: {vulnerability.fixed_versions.join(', ')}
                </li>
              )}
            </ul>
          </div>
        )}
      </div>

      {/* 3. Static Reachability */}
      <div className="accordion-item">
        <button
          type="button"
          className="accordion-header"
          onClick={() => toggleSection('reachability')}
          aria-expanded={openSections.reachability}
        >
          <span>3. Static AST Reachability</span>
          <span>{openSections.reachability ? '▲' : '▼'}</span>
        </button>
        {openSections.reachability && (
          <div className="accordion-body">
            {reachability ? (
              <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                <li style={{ color: reachability.status === 'REACHABLE' ? 'var(--status-red-text)' : reachability.status === 'NOT_REACHABLE' ? 'var(--status-green-text)' : 'var(--status-amber-text)', fontWeight: 600 }}>
                  {reachability.status === 'REACHABLE' ? '🔴 REACHABLE' : reachability.status === 'NOT_REACHABLE' ? '🟢 NOT REACHABLE' : '🟡 UNKNOWN REACHABILITY'}
                </li>
                {reachability.entry_point && (
                  <li style={{ color: 'var(--status-green-text)', fontWeight: 500 }}>
                    ✓ Reachable entry point: <code className="code-pill">{reachability.entry_point}</code>
                  </li>
                )}
                {reachability.target_symbol && (
                  <li style={{ color: 'var(--status-green-text)', fontWeight: 500 }}>
                    ✓ Evaluated symbol: <code className="code-pill">{reachability.target_symbol}</code>
                  </li>
                )}
                {reachability.call_site && (
                  <li style={{ color: 'var(--color-text-secondary)' }}>
                    • Call site location: <code className="code-pill">{reachability.call_site}</code>
                  </li>
                )}
                {reachability.uncertainty_reason && (
                  <li style={{ color: 'var(--status-amber-text)' }}>
                    ⚠️ Reason for uncertainty: {reachability.uncertainty_reason}
                  </li>
                )}
              </ul>
            ) : (
              <p style={{ color: 'var(--color-text-secondary)' }}>Reachability analysis not evaluated for this finding.</p>
            )}
          </div>
        )}
      </div>

      {/* 4. Context & Attacker Control */}
      <div className="accordion-item">
        <button
          type="button"
          className="accordion-header"
          onClick={() => toggleSection('context')}
          aria-expanded={openSections.context}
        >
          <span>4. Attacker Control & Context Analysis</span>
          <span>{openSections.context ? '▲' : '▼'}</span>
        </button>
        {openSections.context && (
          <div className="accordion-body">
            {context ? (
              <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                <li style={{ color: context.status === 'CONFIRMED' ? 'var(--status-red-text)' : context.status === 'NOT_ESTABLISHED' ? 'var(--status-green-text)' : 'var(--status-amber-text)', fontWeight: 600 }}>
                  {context.status === 'CONFIRMED' ? '🔴 ATTACKER CONTROL CONFIRMED' : context.status === 'NOT_ESTABLISHED' ? '🟢 NOT ESTABLISHED (BENIGN / CONSTANT)' : '🟡 ATTACKER CONTROL UNKNOWN'}
                </li>
                {context.source && (
                  <li style={{ color: 'var(--status-green-text)', fontWeight: 500 }}>
                    ✓ Attacker-controlled input source: <code className="code-pill">{context.source.expression}</code> ({context.source.source_type})
                  </li>
                )}
                {context.sink && (
                  <li style={{ color: 'var(--status-green-text)', fontWeight: 500 }}>
                    ✓ Vulnerable sink target: <code className="code-pill">{context.sink}</code>
                  </li>
                )}
                {context.uncertainty_reason && (
                  <li style={{ color: 'var(--status-amber-text)' }}>
                    ⚠️ Uncertainty reason: {context.uncertainty_reason}
                  </li>
                )}
              </ul>
            ) : (
              <p style={{ color: 'var(--color-text-secondary)' }}>Context analysis not evaluated for this finding.</p>
            )}
          </div>
        )}
      </div>

      {/* 5. Verdict Rationale */}
      <div className="accordion-item">
        <button
          type="button"
          className="accordion-header"
          onClick={() => toggleSection('verdict')}
          aria-expanded={openSections.verdict}
        >
          <span>5. Authoritative Verdict Determination</span>
          <span>{openSections.verdict ? '▲' : '▼'}</span>
        </button>
        {openSections.verdict && (
          <div className="accordion-body">
            <ul style={{ listStyle: 'none', display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
              <li>
                Final Verdict: <strong style={{ color: 'var(--color-text-primary)' }}>{verdict}</strong>
              </li>
              <li>
                Confidence Level:{' '}
                <span
                  className={`badge ${finding.confidence >= 0.8 ? 'badge-green' : finding.confidence >= 0.5 ? 'badge-amber' : 'badge-gray'}`}
                  style={{ fontSize: '0.75rem', verticalAlign: 'middle' }}
                >
                  {finding.confidence >= 0.8 ? 'HIGH' : finding.confidence >= 0.5 ? 'MEDIUM' : 'LOW'}
                </span>{' '}
                <span style={{ fontSize: '0.8rem', color: 'var(--color-text-tertiary)', marginLeft: '0.25rem' }}>
                  (Qualitative heuristic assessment — uncalibrated score: {(finding.confidence * 100).toFixed(0)}%)
                </span>
              </li>
              {notes && (
                <li style={{ marginTop: '0.25rem', color: 'var(--color-text-secondary)' }}>
                  Rationale: {notes}
                </li>
              )}
            </ul>
          </div>
        )}
      </div>
    </div>
  );
};
