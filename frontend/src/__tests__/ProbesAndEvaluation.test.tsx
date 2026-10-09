import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { ProbesView } from '../views/ProbesView';
import { ProbeSpecificationCard } from '../components/ProbeSpecificationCard';
import type { ProbePlanReport, ProbeSpecification } from '../types/api';
import { acsaApi } from '../api/client';

describe('ProbesView Component', () => {
  const sampleProbe: ProbeSpecification = {
    probe_id: 'probe-1',
    finding_id: 'finding-1',
    probe_type: 'ROUTE_EXECUTION',
    target_component: 'express',
    target_symbol: 'router.handle',
    entry_point: 'POST /login',
    input_source: 'req.body',
    uncertainty_reason: 'Dynamic route registration prevents static dispatch verification.',
    missing_evidence: 'Runtime HTTP dispatch showing whether POST /login reaches target router.',
    required_observation: 'HTTP request to POST /login triggers execution of registered router callback.',
    success_condition: 'Request dispatches to target middleware callback.',
    failure_condition: 'Request routes to 404 or alternate handler without invoking router.',
    safety_constraints: [
      'Do not execute repository npm lifecycle scripts or arbitrary code.',
      'Use benign probe marker strings; never send destructive or exploit payloads.',
      'Observe in an isolated sandbox or pre-configured test environment only.',
    ],
    expected_verdict_if_confirmed: 'PROVEN_EXPOSURE',
    expected_verdict_if_not_confirmed: 'PROVEN_NOT_AFFECTED',
    priority_rank: 1,
    status: 'PENDING',
    created_at: '2026-10-09T00:00:00Z',
    metadata: {},
  };

  const sampleReport: ProbePlanReport = {
    repository_path: 'tests/fixtures/nodegoat',
    total_unknown_findings: 1,
    total_probes_generated: 1,
    probes_by_type: { ROUTE_EXECUTION: 1 },
    probes: [sampleProbe],
    summary: 'Generated 1 dynamic probe specification.',
    created_at: '2026-10-09T00:00:00Z',
  };

  it('renders defensive execution boundary and probe specification details', () => {
    const handlePlan = vi.fn();
    render(
      <ProbesView
        probePlan={sampleReport}
        isLoading={false}
        onPlanProbes={handlePlan}
      />
    );

    // Defensive execution notice
    expect(screen.getByText(/ACSA does not automatically execute repository code/i)).toBeInTheDocument();

    // Probe details
    expect(screen.getByText('ROUTE EXECUTION')).toBeInTheDocument();
    expect(screen.getByText('express')).toBeInTheDocument();
    expect(screen.getByText(/Dynamic route registration prevents static dispatch verification/i)).toBeInTheDocument();
    expect(screen.getByText(/Runtime HTTP dispatch showing whether/i)).toBeInTheDocument();
    expect(screen.getByText(/HTTP request to POST \/login triggers execution/i)).toBeInTheDocument();

    // Safety constraints
    expect(screen.getByText(/Do not execute repository npm lifecycle scripts/i)).toBeInTheDocument();
  });

  it('allows evaluating external observation against probe specification', async () => {
    vi.spyOn(acsaApi, 'evaluateProbe').mockResolvedValueOnce({
      evaluation_id: 'eval-1',
      probe_id: 'probe-1',
      finding_id: 'finding-1',
      evaluation_status: 'CONFIRMED',
      original_verdict: 'UNKNOWN',
      resolved_verdict: 'PROVEN_EXPOSURE',
      rationale: 'Empirical runtime observation confirmed condition. Transitioned to PROVEN_EXPOSURE.',
      updated_evidence_ids: ['ev-probe-1'],
      evaluated_at: '2026-10-09T00:00:00Z',
    });

    render(<ProbeSpecificationCard probe={sampleProbe} />);

    // Open evaluator
    const toggleBtn = screen.getByRole('button', { name: /Evaluate External Observation/i });
    fireEvent.click(toggleBtn);

    // Form elements
    expect(screen.getByText('Safe Empirical Observation Evaluation')).toBeInTheDocument();
    const submitBtn = screen.getByRole('button', { name: /Submit Observation to API/i });
    fireEvent.click(submitBtn);

    // Wait for resolution
    await waitFor(() => {
      expect(screen.getByText(/Transitioned to PROVEN_EXPOSURE/i)).toBeInTheDocument();
    });
  });
});
