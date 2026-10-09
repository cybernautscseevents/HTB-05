import React from 'react';
import type { Finding } from '../types/api';

interface ExposurePathProps {
  finding: Finding;
}

export const ExposurePath: React.FC<ExposurePathProps> = ({ finding }) => {
  const { context, reachability, component } = finding;

  // Prefer rich structured data flow steps from ContextAnalysis if available
  if (context && context.data_flow_steps && context.data_flow_steps.length > 0) {
    return (
      <div className="exposure-path-container">
        <h4 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.75rem', color: 'var(--color-text-primary)' }}>
          Verified Attacker-to-Sink Data Flow Path
        </h4>
        <div className="exposure-step-list">
          {context.data_flow_steps.map((step, idx) => {
            const isLast = idx === context.data_flow_steps.length - 1;
            return (
              <React.Fragment key={idx}>
                <div className="exposure-step">
                  <span className="exposure-step-indicator">{step.step_type?.replace(/_/g, ' ') || 'STEP'}</span>
                  <div className="exposure-step-content">
                    <div className="exposure-step-title">{step.expression}</div>
                    {step.description && <div style={{ fontSize: '0.75rem', color: 'var(--color-text-tertiary)' }}>{step.description}</div>}
                    {step.location && (
                      <div className="exposure-step-detail">
                        {step.location.file_path}
                        {step.location.line_number ? `:${step.location.line_number}` : ''}
                      </div>
                    )}
                  </div>
                </div>
                {!isLast && <div className="step-arrow" aria-hidden="true">↓</div>}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    );
  }

  // Fallback to reachability evidence_path if present
  if (reachability && reachability.evidence_path && reachability.evidence_path.length > 0) {
    return (
      <div className="exposure-path-container">
        <h4 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.75rem', color: 'var(--color-text-primary)' }}>
          Static Reachability Call Chain
        </h4>
        <div className="exposure-step-list">
          {reachability.evidence_path.map((hop, idx) => {
            const isLast = idx === reachability.evidence_path.length - 1;
            return (
              <React.Fragment key={idx}>
                <div className="exposure-step">
                  <span className="exposure-step-indicator">
                    {idx === 0 ? 'ENTRY' : isLast ? 'SINK' : `HOP ${idx}`}
                  </span>
                  <div className="exposure-step-content">
                    <div className="exposure-step-title" style={{ fontFamily: 'var(--font-mono)' }}>
                      {hop}
                    </div>
                  </div>
                </div>
                {!isLast && <div className="step-arrow" aria-hidden="true">↓</div>}
              </React.Fragment>
            );
          })}
        </div>
      </div>
    );
  }

  // Single entry point to symbol if available
  if (reachability && reachability.entry_point && reachability.target_symbol) {
    return (
      <div className="exposure-path-container">
        <h4 style={{ fontSize: '0.875rem', fontWeight: 600, marginBottom: '0.75rem', color: 'var(--color-text-primary)' }}>
          Exposure Edge
        </h4>
        <div className="exposure-step-list">
          <div className="exposure-step">
            <span className="exposure-step-indicator">HTTP ENTRY</span>
            <div className="exposure-step-content">
              <div className="exposure-step-title">{reachability.entry_point}</div>
            </div>
          </div>
          <div className="step-arrow" aria-hidden="true">↓</div>
          <div className="exposure-step">
            <span className="exposure-step-indicator">VULNERABLE SYMBOL</span>
            <div className="exposure-step-content">
              <div className="exposure-step-title">{reachability.target_symbol}</div>
              <div className="exposure-step-detail">Package: {component?.name || 'Component'}</div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  // If no path is established
  return (
    <div style={{ padding: '0.75rem', background: 'var(--color-bg-subtle)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--color-border-base)', color: 'var(--color-text-secondary)', fontSize: '0.825rem' }}>
      No active exposure path established in static or context evidence.
    </div>
  );
};
