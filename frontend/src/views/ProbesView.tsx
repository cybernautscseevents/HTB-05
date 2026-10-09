import React from 'react';
import type { ProbePlanReport } from '../types/api';
import { ProbeSpecificationCard } from '../components/ProbeSpecificationCard';
import { EmptyState } from '../components/EmptyState';
import { LoadingState } from '../components/LoadingState';

interface ProbesViewProps {
  probePlan: ProbePlanReport | null;
  isLoading: boolean;
  onPlanProbes: () => void;
  selectedFindingId?: string | null;
}

export const ProbesView: React.FC<ProbesViewProps> = ({
  probePlan,
  isLoading,
  onPlanProbes,
  selectedFindingId,
}) => {
  if (isLoading) {
    return (
      <LoadingState
        message="Planning Uncertainty-Guided Dynamic Probes..."
        subtext="Analyzing UNKNOWN findings, identifying missing evidence artifacts, and constructing declarative safety constraints."
      />
    );
  }

  if (!probePlan || !probePlan.probes || probePlan.probes.length === 0) {
    return (
      <div>
        <div className="section-header">
          <h2 className="section-title">Uncertainty-Guided Dynamic Probes</h2>
          <p className="section-subtitle">
            What evidence should we collect next to resolve UNKNOWN verdicts?
          </p>
        </div>

        {/* Explicit Defensive Policy Notice */}
        <div className="amber-banner" style={{ background: 'var(--color-bg-base)', border: '1px solid var(--color-border-strong)' }}>
          🛡️ <strong>Execution Boundary Notice:</strong> ACSA does not automatically execute repository code or lifecycle scripts. It produces targeted declarative probe specifications and safely evaluates externally supplied observations.
        </div>

        <EmptyState
          title="No dynamic probes planned yet"
          description="Generate targeted probe specifications for UNKNOWN findings requiring empirical runtime observations."
          actionLabel="Plan Dynamic Probes"
          onAction={onPlanProbes}
        />
      </div>
    );
  }

  // Filter by selected finding if passed
  const probesToDisplay = selectedFindingId
    ? (probePlan.probes || []).filter((p) => p.finding_id === selectedFindingId)
    : (probePlan.probes || []);

  return (
    <div>
      <div className="section-header">
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div>
            <h2 className="section-title">Uncertainty-Guided Dynamic Probes</h2>
            <p className="section-subtitle">
              Generated {probePlan.total_probes_generated} targeted probe specification{probePlan.total_probes_generated === 1 ? '' : 's'} across {probePlan.total_unknown_findings} UNKNOWN findings
            </p>
          </div>
          <button
            type="button"
            className="btn btn-secondary btn-sm"
            onClick={onPlanProbes}
          >
            Re-Plan Probes
          </button>
        </div>
      </div>

      {/* Explicit Defensive Policy Notice */}
      <div className="amber-banner" style={{ background: 'var(--color-bg-base)', border: '1px solid var(--color-border-strong)' }}>
        🛡️ <strong>Defensive Execution Boundary:</strong> ACSA does not automatically execute repository code, install dependencies, or run untrusted lifecycle scripts. Probes are declarative specifications to be executed in isolated sandboxes or instrumented test runners.
      </div>

      {/* Probe Breakdown by Type */}
      <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap', marginBottom: '1.25rem' }}>
        {Object.entries(probePlan.probes_by_type || {}).map(([type, count]) => (
          <span key={type} className="badge badge-amber">
            <span>{type?.replace(/_/g, ' ') || type}:</span>
            <strong>{count}</strong>
          </span>
        ))}
      </div>

      {/* Probes List */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
        {probesToDisplay.map((probe) => (
          <ProbeSpecificationCard key={probe.probe_id} probe={probe} />
        ))}
      </div>
    </div>
  );
};
