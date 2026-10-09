import React, { useState } from 'react';
import type { ProbeEvaluation, ProbeObservation, ProbeSpecification } from '../types/api';
import { acsaApi } from '../api/client';
import { VerdictBadge } from './VerdictBadge';

interface ProbeSpecificationCardProps {
  probe: ProbeSpecification;
}

export const ProbeSpecificationCard: React.FC<ProbeSpecificationCardProps> = ({ probe }) => {
  const [showEvaluate, setShowEvaluate] = useState(false);
  const [observedState, setObservedState] = useState<'true' | 'false' | 'null'>('true');
  const [notes, setNotes] = useState('');
  const [isEvaluating, setIsEvaluating] = useState(false);
  const [evaluationResult, setEvaluationResult] = useState<ProbeEvaluation | null>(null);
  const [evaluateError, setEvaluateError] = useState<string | null>(null);

  const handleEvaluate = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsEvaluating(true);
    setEvaluateError(null);

    const observedValue = observedState === 'true' ? true : observedState === 'false' ? false : null;
    const observation: ProbeObservation = {
      probe_id: probe.probe_id,
      finding_id: probe.finding_id,
      observed: observedValue,
      evidence_payload: {
        tested_target: probe.target_component,
        symbol: probe.target_symbol,
        entry: probe.entry_point,
      },
      observer_notes: notes || undefined,
    };

    try {
      const evaluation = await acsaApi.evaluateProbe(probe, observation, 'UNKNOWN');
      setEvaluationResult(evaluation);
    } catch (err: unknown) {
      setEvaluateError(err instanceof Error ? err.message : 'Evaluation failed');
    } finally {
      setIsEvaluating(false);
    }
  };

  return (
    <div className="card" style={{ borderLeft: '4px solid var(--status-amber-text)' }}>
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', flexWrap: 'wrap', gap: '0.75rem', marginBottom: '0.75rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem' }}>
            <span className="badge badge-amber">
              <span className="badge-dot" aria-hidden="true" />
              <span>{probe.probe_type?.replace(/_/g, ' ') || 'PROBE'}</span>
            </span>
            <span style={{ fontSize: '0.75rem', color: 'var(--color-text-tertiary)', fontFamily: 'var(--font-mono)' }}>
              Priority #{probe.priority_rank}
            </span>
          </div>
          <h4 style={{ fontSize: '1.05rem', fontWeight: 700, color: 'var(--color-text-primary)' }}>
            Target Component: <code className="code-pill">{probe.target_component}</code>
            {probe.target_symbol && (
              <span style={{ fontWeight: 400, color: 'var(--color-text-secondary)', marginLeft: '0.5rem' }}>
                • Symbol: <code className="code-pill">{probe.target_symbol}</code>
              </span>
            )}
          </h4>
        </div>
        <button
          type="button"
          className="btn btn-secondary btn-sm"
          onClick={() => setShowEvaluate(!showEvaluate)}
        >
          {showEvaluate ? 'Hide Observation Evaluator' : 'Evaluate External Observation'}
        </button>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem', margin: '0.75rem 0' }}>
        <div style={{ background: 'var(--color-bg-subtle)', border: '1px solid var(--color-border-base)', borderRadius: 'var(--radius-sm)', padding: '0.75rem' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-tertiary)', textTransform: 'uppercase' }}>
            Why UNKNOWN
          </div>
          <p style={{ fontSize: '0.825rem', color: 'var(--color-text-primary)', marginTop: '0.25rem' }}>
            {probe.uncertainty_reason}
          </p>
        </div>

        <div style={{ background: 'var(--color-bg-subtle)', border: '1px solid var(--color-border-base)', borderRadius: 'var(--radius-sm)', padding: '0.75rem' }}>
          <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--color-text-tertiary)', textTransform: 'uppercase' }}>
            Missing Evidence
          </div>
          <p style={{ fontSize: '0.825rem', color: 'var(--color-text-primary)', marginTop: '0.25rem' }}>
            {probe.missing_evidence}
          </p>
        </div>
      </div>

      <div style={{ margin: '0.75rem 0', fontSize: '0.85rem' }}>
        <div>
          <strong style={{ color: 'var(--color-text-secondary)' }}>Required Observation:</strong>{' '}
          <span style={{ color: 'var(--color-text-primary)' }}>{probe.required_observation}</span>
        </div>
        {probe.entry_point && (
          <div style={{ marginTop: '0.25rem' }}>
            <strong style={{ color: 'var(--color-text-secondary)' }}>HTTP Entry Point:</strong>{' '}
            <code className="code-pill">{probe.entry_point}</code>
          </div>
        )}
      </div>

      {/* Expected Verdict Transition */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '1.5rem', flexWrap: 'wrap', padding: '0.65rem 0.85rem', background: 'var(--color-bg-subtle)', borderRadius: 'var(--radius-sm)', border: '1px solid var(--color-border-subtle)', margin: '0.75rem 0' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}>
          <span style={{ color: 'var(--color-text-secondary)' }}>If Confirmed:</span>
          <VerdictBadge verdict={probe.expected_verdict_if_confirmed} size="sm" />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.8rem' }}>
          <span style={{ color: 'var(--color-text-secondary)' }}>If Refuted:</span>
          <VerdictBadge verdict={probe.expected_verdict_if_not_confirmed} size="sm" />
        </div>
      </div>

      {/* Defensive Safety Constraints */}
      <div style={{ marginTop: '0.75rem' }}>
        <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-text-tertiary)', textTransform: 'uppercase', marginBottom: '0.25rem' }}>
          Enforced Defensive Safety Constraints
        </div>
        <ul style={{ listStyle: 'none', display: 'flex', flexWrap: 'wrap', gap: '0.35rem' }}>
          {(probe.safety_constraints || []).map((constraint, idx) => (
            <li
              key={idx}
              style={{
                fontSize: '0.725rem',
                padding: '0.15rem 0.45rem',
                background: 'var(--color-bg-muted)',
                borderRadius: 'var(--radius-sm)',
                color: 'var(--color-text-secondary)',
                border: '1px solid var(--color-border-base)',
              }}
            >
              🛡️ {constraint}
            </li>
          ))}
        </ul>
      </div>

      {/* Interactive External Observation Evaluator */}
      {showEvaluate && (
        <div style={{ marginTop: '1rem', paddingTop: '1rem', borderTop: '1px solid var(--color-border-base)' }}>
          <h5 style={{ fontSize: '0.875rem', fontWeight: 600, color: 'var(--color-text-primary)', marginBottom: '0.5rem' }}>
            Safe Empirical Observation Evaluation
          </h5>
          <p style={{ fontSize: '0.775rem', color: 'var(--color-text-tertiary)', marginBottom: '0.75rem' }}>
            ACSA does not execute repository code. Supply structured observations from isolated runtime tests or manual analyst verification to resolve the UNKNOWN verdict.
          </p>

          <form onSubmit={handleEvaluate} style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
            <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
              <label style={{ fontSize: '0.825rem', fontWeight: 600 }}>Empirical Condition Observed:</label>
              <label style={{ fontSize: '0.825rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <input
                  type="radio"
                  name={`observed-${probe.probe_id}`}
                  value="true"
                  checked={observedState === 'true'}
                  onChange={() => setObservedState('true')}
                />
                Confirmed (True)
              </label>
              <label style={{ fontSize: '0.825rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <input
                  type="radio"
                  name={`observed-${probe.probe_id}`}
                  value="false"
                  checked={observedState === 'false'}
                  onChange={() => setObservedState('false')}
                />
                Refuted (False)
              </label>
              <label style={{ fontSize: '0.825rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                <input
                  type="radio"
                  name={`observed-${probe.probe_id}`}
                  value="null"
                  checked={observedState === 'null'}
                  onChange={() => setObservedState('null')}
                />
                Inconclusive
              </label>
            </div>

            <div>
              <label htmlFor={`notes-${probe.probe_id}`} style={{ display: 'block', fontSize: '0.8rem', fontWeight: 600, marginBottom: '0.25rem' }}>
                Observer Notes:
              </label>
              <input
                id={`notes-${probe.probe_id}`}
                type="text"
                className="repo-input"
                style={{ width: '100%' }}
                placeholder="e.g. Runtime HTTP probe confirmed execution of router callback"
                value={notes}
                onChange={(e) => setNotes(e.target.value)}
              />
            </div>

            <div>
              <button
                type="submit"
                className="btn btn-primary btn-sm"
                disabled={isEvaluating}
              >
                {isEvaluating ? 'Evaluating...' : 'Submit Observation to API'}
              </button>
            </div>
          </form>

          {evaluateError && (
            <div className="error-banner" style={{ marginTop: '0.75rem' }}>
              {evaluateError}
            </div>
          )}

          {evaluationResult && (
            <div style={{ marginTop: '0.75rem', padding: '0.75rem', background: 'var(--color-bg-base)', border: '1px solid var(--color-border-strong)', borderRadius: 'var(--radius-sm)' }}>
              <div style={{ fontSize: '0.775rem', fontWeight: 700, color: 'var(--color-text-secondary)', textTransform: 'uppercase' }}>
                Evaluation Outcome:
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '0.35rem' }}>
                <span style={{ fontSize: '0.825rem' }}>Original Verdict: <strong>{evaluationResult.original_verdict}</strong></span>
                <span>→</span>
                <span style={{ fontSize: '0.825rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                  Resolved Verdict: <VerdictBadge verdict={evaluationResult.resolved_verdict} size="sm" />
                </span>
              </div>
              <p style={{ fontSize: '0.8rem', color: 'var(--color-text-secondary)', marginTop: '0.35rem' }}>
                <strong>Rationale:</strong> {evaluationResult.rationale}
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
};
