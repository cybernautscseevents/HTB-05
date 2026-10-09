import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import React from 'react';
import { FindingDetailView } from '../views/FindingDetailView';
import type { Finding } from '../types/api';

describe('FindingDetailView Component', () => {
  const exposedFinding: Finding = {
    id: 'finding-1',
    vulnerability: {
      id: 'GHSA-296q-j2x6-9328',
      aliases: ['CVE-2021-23337'],
      summary: 'Command Injection in lodash.template',
      details: 'Full details of vulnerability',
      severity: 'HIGH',
      affected_ranges: ['< 4.17.21'],
      fixed_versions: ['4.17.21'],
      vulnerable_symbols: ['template'],
      database_specific: {},
    },
    component: {
      name: 'lodash',
      version: '4.17.19',
      is_direct: true,
      manifest_path: 'package.json',
      lockfile_path: 'package-lock.json',
    },
    verdict: 'PROVEN_EXPOSURE',
    applicability_status: 'AFFECTED',
    source_observation_id: 'obs-1',
    source_artifact_path: 'package-lock.json',
    source: 'OSV_ADVISORY',
    evidence_ids: ['ev-1', 'ev-2'],
    confidence: 1.0,
    created_at: '2026-10-09T00:00:00Z',
    notes: 'Proven reachable from HTTP route',
    reachability: {
      status: 'REACHABLE',
      target_symbol: 'template',
      entry_point: 'POST /render',
      call_site: 'app/routes/index.js:14',
      evidence_path: ['POST /render', 'helper()', 'lodash.template'],
      uncertainty_reason: null,
      missing_evidence: null,
      confidence: 1.0,
      evidence_ids: ['ev-1'],
      metadata: {},
    },
    context: {
      status: 'CONFIRMED',
      source: {
        source_type: 'body',
        expression: 'req.body.template',
        location: { file_path: 'app/routes/index.js', line_number: 12 },
        entry_point: 'POST /render',
      },
      entry_point: 'POST /render',
      sink: 'lodash.template',
      sink_location: { file_path: 'app/routes/index.js', line_number: 14 },
      data_flow_path: ['POST /render', 'req.body.template', 'lodash.template'],
      data_flow_steps: [
        { step_type: 'http_entry', expression: 'POST /render', location: { file_path: 'app/routes/index.js', line_number: 10 }, description: 'HTTP route handler' },
        { step_type: 'input_source', expression: 'req.body.template', location: { file_path: 'app/routes/index.js', line_number: 12 }, description: 'Attacker input parameter' },
        { step_type: 'sink_call', expression: 'lodash.template()', location: { file_path: 'app/routes/index.js', line_number: 14 }, description: 'Vulnerable template sink' },
      ],
      uncertainty_reason: null,
      missing_evidence: null,
      confidence: 1.0,
      evidence_ids: ['ev-2'],
      metadata: {},
    },
    uncertainty_reason: null,
    missing_evidence: null,
  };

  const unknownFinding: Finding = {
    ...exposedFinding,
    id: 'finding-2',
    verdict: 'UNKNOWN',
    uncertainty_reason: 'Dynamic route registration in fastify prevents static AST dispatch verification.',
    missing_evidence: 'Runtime HTTP dispatch showing whether POST /login reaches target.',
    reachability: {
      status: 'UNKNOWN',
      target_symbol: 'authenticate',
      entry_point: null,
      call_site: null,
      evidence_path: [],
      uncertainty_reason: 'Dynamic route registration prevents static dispatch verification.',
      missing_evidence: 'Runtime HTTP dispatch log.',
      confidence: 0.5,
      evidence_ids: [],
      metadata: {},
    },
    context: null,
  };

  it('renders PROVEN_EXPOSURE with Why It Matters and Exposure Path hops', () => {
    const handleBack = vi.fn();
    const handleRemediation = vi.fn();
    const handleProbes = vi.fn();

    render(
      <FindingDetailView
        finding={exposedFinding}
        remediationCandidate={null}
        onBack={handleBack}
        onViewRemediation={handleRemediation}
        onViewProbes={handleProbes}
      />
    );

    // Header info
    expect(screen.getAllByText('lodash').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('GHSA-296q-j2x6-9328').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByRole('status', { name: /Verdict: PROVEN EXPOSURE/i })).toBeInTheDocument();

    // Why it matters
    expect(screen.getByText(/Proven security exposure/i)).toBeInTheDocument();

    // Exposure path hops
    expect(screen.getByText('Verified Attacker-to-Sink Data Flow Path')).toBeInTheDocument();
    expect(screen.getAllByText('POST /render').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('req.body.template').length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('lodash.template()')).toBeInTheDocument();

    // Evidence provenance checks
    expect(screen.getByText(/Exact installed version/i)).toBeInTheDocument();
    expect(screen.getAllByText('4.17.19').length).toBeGreaterThanOrEqual(1);
  });

  it('renders UNKNOWN finding with first-class security warning and probe callout', () => {
    const handleBack = vi.fn();
    const handleRemediation = vi.fn();
    const handleProbes = vi.fn();

    render(
      <FindingDetailView
        finding={unknownFinding}
        remediationCandidate={null}
        onBack={handleBack}
        onViewRemediation={handleRemediation}
        onViewProbes={handleProbes}
      />
    );

    // UNKNOWN security warning
    expect(screen.getByText('UNKNOWN — First-Class Security State')).toBeInTheDocument();
    expect(screen.getByText(/ACSA cannot currently prove whether this finding is reachable/i)).toBeInTheDocument();
    expect(screen.getAllByText(/Dynamic route registration/i).length).toBeGreaterThanOrEqual(1);

    // Action to view targeted probe
    const probeBtn = screen.getByRole('button', { name: /View Targeted Probe Specification/i });
    fireEvent.click(probeBtn);
    expect(handleProbes).toHaveBeenCalledWith('finding-2');
  });

  it('renders PROVEN_AFFECTED finding explaining installed version is affected without implying application exposure', () => {
    const affectedUnreachableFinding: Finding = {
      ...exposedFinding,
      id: 'finding-affected-unreachable',
      verdict: 'PROVEN_AFFECTED',
      reachability: {
        status: 'NOT_REACHABLE',
        target_symbol: 'template',
        entry_point: null,
        call_site: null,
        evidence_path: [],
        uncertainty_reason: null,
        missing_evidence: null,
        confidence: 0.95,
        evidence_ids: [],
        metadata: {},
      },
      context: null,
      notes: 'Component is affected, but symbol is not reachable.',
    };

    render(
      <FindingDetailView
        finding={affectedUnreachableFinding}
        remediationCandidate={null}
        onBack={vi.fn()}
        onViewRemediation={vi.fn()}
        onViewProbes={vi.fn()}
      />
    );

    // Why it matters explains installed version is affected, but unreachable, and applicability != exposure
    expect(screen.getByText(/installed version is confirmed affected/i)).toBeInTheDocument();
    expect(screen.getByText(/proven not reachable in application source code/i)).toBeInTheDocument();
    expect(screen.getByText(/Exploitability is not implied from component applicability alone/i)).toBeInTheDocument();
  });

  it('renders audited qualitative confidence level instead of misleading deterministic confidence percentage in evidence provenance section', () => {
    render(
      <FindingDetailView
        finding={exposedFinding}
        remediationCandidate={null}
        onBack={vi.fn()}
        onViewRemediation={vi.fn()}
        onViewProbes={vi.fn()}
      />
    );

    // Accordion section 5 (Authoritative Verdict Determination) is open by default
    expect(screen.getByText('5. Authoritative Verdict Determination')).toBeInTheDocument();

    // Audited label is displayed with qualitative badge
    expect(screen.getByText(/Confidence Level:/i)).toBeInTheDocument();
    expect(screen.getByText('HIGH')).toBeInTheDocument();
    expect(screen.getByText(/Qualitative heuristic assessment/i)).toBeInTheDocument();

    // Must NOT claim "Deterministic Confidence: 95%" or "Deterministic Confidence: 100%"
    expect(screen.queryByText(/Deterministic Confidence/i)).not.toBeInTheDocument();
  });

  it('renders semver GHSA-c2qf-rxjj-qqgw without displaying generic word "the" or claiming false unreachable status', () => {
    const semverFinding: Finding = {
      id: 'finding-semver-c2qf',
      vulnerability: {
        id: 'GHSA-c2qf-rxjj-qqgw',
        aliases: ['CVE-2022-25883'],
        summary: 'semver vulnerable to Regular Expression Denial of Service',
        details: 'Vulnerable via the function new Range',
        severity: 'HIGH',
        affected_ranges: ['< 5.7.2'],
        fixed_versions: ['5.7.2'],
        vulnerable_symbols: [], // Correct: NO generic word 'the'
        database_specific: {},
      },
      component: {
        name: 'semver',
        version: '5.7.0',
        is_direct: false,
        manifest_path: null,
        lockfile_path: 'package-lock.json',
      },
      verdict: 'UNKNOWN',
      applicability_status: 'AFFECTED',
      source_observation_id: 'obs-semver',
      source_artifact_path: 'package-lock.json',
      source: 'OSV_ADVISORY',
      evidence_ids: ['ev-semver'],
      confidence: 0.4,
      created_at: '2026-10-09T00:00:00Z',
      notes: 'Advisory is applicable, but reachability is unknown: Advisory provides no usable vulnerable symbol/function data. UNKNOWN != SAFE.',
      reachability: {
        status: 'UNKNOWN',
        target_symbol: null, // Correct: NOT 'the'
        entry_point: null,
        call_site: null,
        evidence_path: [],
        uncertainty_reason: 'Advisory provides no usable vulnerable symbol/function data',
        missing_evidence: null,
        confidence: 0.5,
        evidence_ids: [],
        metadata: {},
      },
      context: null,
      uncertainty_reason: 'Advisory provides no usable vulnerable symbol/function data',
      missing_evidence: 'Resolution of reachability or dynamic symbol access is required',
    };

    render(
      <FindingDetailView
        finding={semverFinding}
        remediationCandidate={null}
        onBack={vi.fn()}
        onViewRemediation={vi.fn()}
        onViewProbes={vi.fn()}
      />
    );

    // Component and Advisory identifiers are present
    expect(screen.getAllByText('semver').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('GHSA-c2qf-rxjj-qqgw').length).toBeGreaterThanOrEqual(1);
    expect(screen.getAllByText('5.7.0').length).toBeGreaterThanOrEqual(1);

    // Must NOT display "the" as an identified vulnerable symbol pill
    expect(screen.queryByText(/Vulnerable symbol identified:/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/Evaluated symbol: the/i)).not.toBeInTheDocument();

    // Must NOT claim "NOT REACHABLE"
    expect(screen.queryByText(/NOT REACHABLE/i)).not.toBeInTheDocument();

    // Must display UNKNOWN security state
    expect(screen.getByText('UNKNOWN — First-Class Security State')).toBeInTheDocument();
    expect(screen.getAllByText(/no usable vulnerable symbol/i).length).toBeGreaterThanOrEqual(1);
  });
});

