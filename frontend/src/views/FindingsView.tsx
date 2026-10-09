import React, { useState, useMemo } from 'react';
import type { Finding, Verdict } from '../types/api';
import { VerdictBadge } from '../components/VerdictBadge';
import { StatusBadge } from '../components/StatusBadge';
import { EmptyState } from '../components/EmptyState';

interface FindingsViewProps {
  findings: Finding[];
  onSelectFinding: (finding: Finding) => void;
  onScan: () => void;
}

export const FindingsView: React.FC<FindingsViewProps> = ({
  findings,
  onSelectFinding,
  onScan,
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [verdictFilter, setVerdictFilter] = useState<string>('ALL');
  const [reachabilityFilter, setReachabilityFilter] = useState<string>('ALL');
  const [sortBy, setSortBy] = useState<'priority' | 'component' | 'advisory'>('priority');

  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const comp = (f.component?.name || '').toLowerCase();
        const adv = (f.vulnerability?.id || '').toLowerCase();
        const sym = f.vulnerability?.vulnerable_symbols ? f.vulnerability.vulnerable_symbols.join(' ').toLowerCase() : '';
        if (!comp.includes(q) && !adv.includes(q) && !sym.includes(q)) {
          return false;
        }
      }

      // Verdict filter
      if (verdictFilter !== 'ALL') {
        if (verdictFilter === 'AFFECTED_GROUP') {
          if (f.verdict !== 'PROVEN_EXPOSURE' && f.verdict !== 'PROVEN_AFFECTED' && f.verdict !== 'POTENTIALLY_AFFECTED') {
            return false;
          }
        } else if (verdictFilter === 'UNKNOWN_GROUP') {
          if (f.verdict !== 'UNKNOWN' && f.verdict !== 'CONTRADICTORY') {
            return false;
          }
        } else if (verdictFilter === 'SAFE_GROUP') {
          if (f.verdict !== 'PROVEN_NOT_AFFECTED') {
            return false;
          }
        } else if (f.verdict !== verdictFilter) {
          return false;
        }
      }

      // Reachability filter
      if (reachabilityFilter !== 'ALL') {
        const rStatus = f.reachability ? f.reachability.status : 'UNKNOWN';
        if (rStatus !== reachabilityFilter) {
          return false;
        }
      }

      return true;
    });
  }, [findings, searchQuery, verdictFilter, reachabilityFilter]);

  const sortedFindings = useMemo(() => {
    return [...filteredFindings].sort((a, b) => {
      if (sortBy === 'component') {
        return (a.component?.name || '').localeCompare(b.component?.name || '');
      }
      if (sortBy === 'advisory') {
        return (a.vulnerability?.id || '').localeCompare(b.vulnerability?.id || '');
      }
      // Priority sorting
      const score = (f: Finding) => {
        if (f.verdict === 'PROVEN_EXPOSURE') return 100;
        if (f.verdict === 'PROVEN_AFFECTED') return 80;
        if (f.verdict === 'POTENTIALLY_AFFECTED') return 60;
        if (f.verdict === 'UNKNOWN') return 50;
        if (f.verdict === 'CONTRADICTORY') return 40;
        if (f.verdict === 'PROVEN_NOT_AFFECTED') return 10;
        return 0;
      };
      return score(b) - score(a);
    });
  }, [filteredFindings, sortBy]);

  if (findings.length === 0) {
    return (
      <EmptyState
        title="No findings available"
        description="Run an analysis to generate evidence-backed security findings for your repository dependencies."
        actionLabel="Scan Repository"
        onAction={onScan}
      />
    );
  }

  const getPriorityLabel = (verdict: Verdict) => {
    switch (verdict) {
      case 'PROVEN_EXPOSURE':
        return <span style={{ color: 'var(--status-red-text)', fontWeight: 700 }}>P1 — Immediate</span>;
      case 'PROVEN_AFFECTED':
        return <span style={{ color: 'var(--status-red-text)', fontWeight: 600 }}>P2 — High</span>;
      case 'POTENTIALLY_AFFECTED':
        return <span style={{ color: 'var(--status-amber-text)', fontWeight: 600 }}>P3 — Medium</span>;
      case 'UNKNOWN':
      case 'CONTRADICTORY':
        return <span style={{ color: 'var(--status-amber-text)', fontWeight: 600 }}>P3 — Action Req</span>;
      case 'PROVEN_NOT_AFFECTED':
        return <span style={{ color: 'var(--status-green-text)', fontWeight: 500 }}>P4 — Safe</span>;
      default:
        return <span style={{ color: 'var(--color-text-tertiary)' }}>P4 — Neutral</span>;
    }
  };

  return (
    <div>
      <div className="section-header">
        <h2 className="section-title">Findings Triage</h2>
        <p className="section-subtitle">
          Showing {sortedFindings.length} of {findings.length} evidence-backed dependency findings
        </p>
      </div>

      {/* Filter and Search Controls */}
      <div className="card" style={{ padding: '0.85rem', marginBottom: '1rem' }}>
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ flex: 1, minWidth: '220px' }}>
            <input
              type="text"
              className="repo-input"
              style={{ width: '100%' }}
              placeholder="Filter by package, advisory ID, or symbol..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              aria-label="Search findings"
            />
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <label htmlFor="verdict-filter-select" style={{ fontSize: '0.775rem', fontWeight: 600, color: 'var(--color-text-secondary)' }}>
              Verdict:
            </label>
            <select
              id="verdict-filter-select"
              className="repo-input"
              style={{ padding: '0.35rem 0.5rem', fontSize: '0.8rem' }}
              value={verdictFilter}
              onChange={(e) => setVerdictFilter(e.target.value)}
            >
              <option value="ALL">All Verdicts</option>
              <option value="PROVEN_EXPOSURE">PROVEN_EXPOSURE (Confirmed)</option>
              <option value="UNKNOWN">UNKNOWN (Needs Evidence)</option>
              <option value="POTENTIALLY_AFFECTED">POTENTIALLY_AFFECTED</option>
              <option value="CONTRADICTORY">CONTRADICTORY</option>
              <option value="PROVEN_NOT_AFFECTED">PROVEN_NOT_AFFECTED (Safe)</option>
              <option value="AFFECTED_GROUP">Any Affected</option>
              <option value="UNKNOWN_GROUP">Any Uncertain / Contradictory</option>
              <option value="SAFE_GROUP">Only Verified Safe</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <label htmlFor="reach-filter-select" style={{ fontSize: '0.775rem', fontWeight: 600, color: 'var(--color-text-secondary)' }}>
              Reachability:
            </label>
            <select
              id="reach-filter-select"
              className="repo-input"
              style={{ padding: '0.35rem 0.5rem', fontSize: '0.8rem' }}
              value={reachabilityFilter}
              onChange={(e) => setReachabilityFilter(e.target.value)}
            >
              <option value="ALL">All States</option>
              <option value="REACHABLE">REACHABLE</option>
              <option value="NOT_REACHABLE">NOT_REACHABLE</option>
              <option value="UNKNOWN">UNKNOWN</option>
            </select>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
            <label htmlFor="sort-select" style={{ fontSize: '0.775rem', fontWeight: 600, color: 'var(--color-text-secondary)' }}>
              Sort:
            </label>
            <select
              id="sort-select"
              className="repo-input"
              style={{ padding: '0.35rem 0.5rem', fontSize: '0.8rem' }}
              value={sortBy}
              onChange={(e) => setSortBy(e.target.value as 'priority' | 'component' | 'advisory')}
            >
              <option value="priority">Priority Severity</option>
              <option value="component">Component Name</option>
              <option value="advisory">Advisory ID</option>
            </select>
          </div>
        </div>
      </div>

      {/* Findings Table */}
      <div className="table-container">
        <table className="data-table">
          <thead>
            <tr>
              <th>Component</th>
              <th>Version</th>
              <th>Advisory</th>
              <th>Verdict</th>
              <th>Reachability</th>
              <th>Priority</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody>
            {sortedFindings.map((finding) => (
              <tr
                key={finding.id}
                className="clickable"
                onClick={() => onSelectFinding(finding)}
              >
                <td>
                  <strong>{finding.component?.name || 'Unknown'}</strong>
                  {finding.component?.is_direct && (
                    <span style={{ fontSize: '0.7rem', color: 'var(--color-text-tertiary)', marginLeft: '0.35rem' }}>
                      (direct)
                    </span>
                  )}
                </td>
                <td>
                  <code className="code-pill">{finding.component?.version || 'unknown'}</code>
                </td>
                <td>
                  <span style={{ fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                    {finding.vulnerability?.id || 'Unknown'}
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
                  {getPriorityLabel(finding.verdict)}
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
                    View Detail
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
