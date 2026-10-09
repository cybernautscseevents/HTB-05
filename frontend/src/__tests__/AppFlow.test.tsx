import '@testing-library/jest-dom/vitest';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import React from 'react';
import { App } from '../App';
import { acsaApi } from '../api/client';
import type { VulnerabilityScanResult } from '../types/api';

describe('App Integration Flow', () => {
  const mockScanResult: VulnerabilityScanResult = {
    repository_path: 'tests/fixtures/nodegoat',
    inventory: {
      components: {
        'lodash': { name: 'lodash', version: '4.17.19', is_direct: true },
      },
      observations: {},
      contradictions: [],
      is_contradictory: false,
      sources: ['package-lock.json'],
    },
    findings: [
      {
        id: 'f-1',
        vulnerability: {
          id: 'GHSA-296q-j2x6-9328',
          aliases: [],
          summary: 'Command injection in template',
          details: null,
          severity: 'HIGH',
          affected_ranges: ['< 4.17.21'],
          fixed_versions: ['4.17.21'],
          vulnerable_symbols: ['template'],
          database_specific: {},
        },
        component: { name: 'lodash', version: '4.17.19', is_direct: true },
        verdict: 'PROVEN_EXPOSURE',
        applicability_status: 'AFFECTED',
        source_observation_id: 'obs-1',
        source_artifact_path: 'package-lock.json',
        source: 'OSV_ADVISORY',
        evidence_ids: ['ev-1'],
        confidence: 1.0,
        created_at: '2026-10-09T00:00:00Z',
        notes: 'Proven reachable',
        reachability: {
          status: 'REACHABLE',
          target_symbol: 'template',
          entry_point: 'POST /render',
          call_site: 'app/routes/index.js:14',
          evidence_path: ['POST /render', 'lodash.template'],
          uncertainty_reason: null,
          missing_evidence: null,
          confidence: 1.0,
          evidence_ids: ['ev-1'],
          metadata: {},
        },
        context: null,
        uncertainty_reason: null,
        missing_evidence: null,
      },
    ],
    vulnerabilities: [],
    evidence: [
      {
        id: 'ev-1',
        source: 'OSV',
        evidence_type: 'OSV_ADVISORY',
        description: 'Exact advisory match',
        provenance: {},
        confidence: 1.0,
        created_at: '2026-10-09T00:00:00Z',
      },
    ],
    queries_executed: 1,
    exact_versions_queried: 1,
    advisories_count: 1,
    affected_count: 1,
    not_affected_count: 0,
    unknown_count: 0,
    osv_available: true,
    errors: [],
    from_cache_count: 0,
    reachability_evaluated: true,
    context_evaluated: true,
    fusion_evaluated: true,
    proven_exposure_count: 1,
    proven_affected_count: 0,
    potentially_affected_count: 0,
    proven_not_affected_count: 0,
    contradictory_count: 0,
  };

  beforeEach(() => {
    vi.restoreAllMocks();
    vi.spyOn(acsaApi, 'checkHealth').mockResolvedValue({ status: 'ok', service: 'acsa-api' });
  });

  it('renders initial empty state, header tabs, and allows scanning', async () => {
    vi.spyOn(acsaApi, 'scanRepository').mockResolvedValue(mockScanResult);
    vi.spyOn(acsaApi, 'remediateRepository').mockResolvedValue({
      repository_path: 'tests/fixtures/nodegoat',
      total_findings_evaluated: 1,
      candidates_generated: 1,
      contradictions_detected: 0,
      candidates: [],
      manifest_patches: {},
      lockfile_regeneration_required: false,
      summary: 'Summary',
      created_at: '2026-10-09T00:00:00Z',
    });

    render(<App />);

    // Header and Brand
    expect(screen.getByText('ACSA')).toBeInTheDocument();
    expect(screen.getByText('Artifact-Centric Security Analysis')).toBeInTheDocument();

    // Initial empty state
    expect(screen.getByText('No repository analyzed yet')).toBeInTheDocument();

    // Trigger Scan
    const scanBtn = screen.getByRole('button', { name: /Scan Repository/i });
    fireEvent.click(scanBtn);

    // Wait for scan results
    await waitFor(() => {
      expect(screen.getByText('Confirmed Exposure')).toBeInTheDocument();
      expect(screen.getByText('High Priority Findings')).toBeInTheDocument();
      expect(screen.getAllByText('lodash').length).toBeGreaterThanOrEqual(1);
    });

    // Navigate to Findings tab
    const findingsTab = screen.getByRole('button', { name: /^Findings/i });
    fireEvent.click(findingsTab);
    expect(screen.getByText('Findings Triage')).toBeInTheDocument();
    expect(screen.getByText('GHSA-296q-j2x6-9328')).toBeInTheDocument();

    // Navigate to Evidence tab
    const evidenceTab = screen.getByRole('button', { name: /Evidence/i });
    fireEvent.click(evidenceTab);
    expect(screen.getByText('Evidence & Provenance Graph')).toBeInTheDocument();
  });
});
