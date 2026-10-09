import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent, act } from '@testing-library/react';
import React from 'react';
import { RemediationView } from '../views/RemediationView';
import { ProofConditionsTable } from '../components/ProofConditionsTable';
import type { ProofVerificationItem, RemediationReport } from '../types/api';

describe('RemediationView Component', () => {
  const sampleReport: RemediationReport = {
    repository_path: 'tests/fixtures/nodegoat',
    total_findings_evaluated: 2,
    candidates_generated: 1,
    contradictions_detected: 0,
    candidates: [
      {
        candidate_id: 'cand-1',
        strategy: 'DIRECT_UPGRADE',
        package_name: 'express',
        current_version: '4.16.4',
        target_version: '4.20.0',
        files_changed: ['package.json'],
        dependencies_affected: ['express'],
        api_impact: 'MINIMAL',
        version_impact: 'MINOR',
        closure_status: 'REQUIRES_VERIFICATION',
        confidence_level: 'LOW',
        lockfile_action: 'REGENERATION_REQUIRED',
        closed_advisories_count: 2,
        total_advisories_count: 2,
        closed_paths_count: 0,
        total_paths_count: 1,
        reason: 'Static reachability remains UNKNOWN; verification required.',
        evidence_ids: ['ev-1'],
        preconditions: ['Repository tests pass'],
        expected_effect: 'Resolves all 2 known advisories',
        status: 'PROPOSED',
        simulated_patch: '--- a/package.json\n+++ b/package.json\n- "express": "4.16.4"\n+ "express": "4.20.0"',
      },
    ],
    manifest_patches: { 'package.json': 'patch content' },
    lockfile_regeneration_required: true,
    summary: 'Generated 1 minimum blast-radius candidate.',
    created_at: '2026-10-09T00:00:00Z',
  };

  it('renders deterministic remediation candidate without arbitrary numeric blast radius scores', () => {
    const handleGenerate = vi.fn();
    render(
      <RemediationView
        repositoryPath="tests/fixtures/nodegoat"
        remediationReport={sampleReport}
        onGenerateRemediation={handleGenerate}
        isLoading={false}
      />
    );

    // Component name and version transition
    expect(screen.getByText('express')).toBeInTheDocument();
    expect(screen.getByText('4.16.4')).toBeInTheDocument();
    expect(screen.getByText('4.20.0')).toBeInTheDocument();

    // Strategy & Advisories
    expect(screen.getByText('DIRECT_UPGRADE')).toBeInTheDocument();
    expect(screen.getByText((_content, element) => element?.textContent === '2 / 2 resolved')).toBeInTheDocument();

    // Closure & Confidence
    expect(screen.getByRole('status', { name: /Status: REQUIRES_VERIFICATION/i })).toBeInTheDocument();
    expect(screen.getByText('LOW')).toBeInTheDocument();

    // Verify button exists
    expect(screen.getByRole('button', { name: /Verify Remediation/i })).toBeInTheDocument();

    // Confirm no numeric score values are shown
    expect(screen.queryByText(/blast radius score/i)).not.toBeInTheDocument();
    expect(screen.queryByText(/0\.25/)).not.toBeInTheDocument();
  });

  it('renders correctly when backend provides results array format', () => {
    const backendFormatReport: RemediationReport = {
      repository_path: 'tests/fixtures/nodegoat',
      total_findings_evaluated: 1,
      remediated_findings_count: 1,
      results: [
        {
          finding_id: 'finding-1',
          package_name: 'lodash',
          current_version: '4.17.11',
          verdict: 'UNKNOWN',
          advisories: ['GHSA-lodash-1'],
          dependency_relation: 'DIRECT',
          candidates: [
            {
              candidate_id: 'cand-lodash-1',
              strategy: 'DIRECT_UPGRADE',
              package_name: 'lodash',
              current_version: '4.17.11',
              target_version: '4.17.21',
              files_changed: ['package.json'],
              dependencies_affected: ['lodash'],
              api_impact: 'MINIMAL',
              version_impact: 'PATCH',
              closure_status: 'EXPECTED_TO_CLOSE',
              confidence_level: 'HIGH',
              lockfile_action: 'REGENERATION_REQUIRED',
              closed_advisories_count: 1,
              total_advisories_count: 1,
              closed_paths_count: 0,
              total_paths_count: 0,
              reason: 'Upgrade to patched patch release.',
              evidence_ids: ['ev-lodash'],
              preconditions: [],
              expected_effect: 'Resolves vulnerability',
              status: 'PROPOSED',
              simulated_patch: null,
            },
          ],
          selected_candidate: null,
          blast_radius_explanation: 'Lowest risk patch upgrade.',
        },
      ],
    };

    render(
      <RemediationView
        repositoryPath="tests/fixtures/nodegoat"
        remediationReport={backendFormatReport}
        onGenerateRemediation={vi.fn()}
        isLoading={false}
      />
    );

    expect(screen.getByText('lodash')).toBeInTheDocument();
    expect(screen.getByText('4.17.11')).toBeInTheDocument();
    expect(screen.getByText('4.17.21')).toBeInTheDocument();
  });

  it('handles contradictory inventory candidate by showing blocked status and clear explanation when clicked', async () => {
    const contradictoryReport: RemediationReport = {
      repository_path: 'tests/fixtures/nodegoat',
      total_findings_evaluated: 1,
      remediated_findings_count: 0,
      contradictions_detected: 1,
      candidates: [
        {
          candidate_id: 'cand-semver-blocked',
          strategy: 'NO_SAFE_CANDIDATE',
          package_name: 'semver',
          current_version: '5.5.0',
          target_version: null,
          files_changed: [],
          dependencies_affected: ['semver'],
          api_impact: 'NONE',
          version_impact: 'NONE',
          closure_status: 'REQUIRES_VERIFICATION',
          confidence_level: 'LOW',
          lockfile_action: 'NONE',
          closed_advisories_count: 0,
          total_advisories_count: 1,
          closed_paths_count: 0,
          total_paths_count: 1,
          reason: 'Contradictory inventory detected for package semver.',
          evidence_ids: ['ev-semver'],
          preconditions: ['Reconcile manifest and lockfile version discrepancies manually'],
          expected_effect: 'None',
          status: 'CONTRADICTION_BLOCKED',
          simulated_patch: null,
        },
      ],
    };

    render(
      <RemediationView
        repositoryPath="tests/fixtures/nodegoat"
        remediationReport={contradictoryReport}
        onGenerateRemediation={vi.fn()}
        isLoading={false}
      />
    );

    // Contradictory inventory badge and warning banner
    expect(screen.getAllByText(/Contradictory Inventory/i).length).toBeGreaterThanOrEqual(1);
    expect(screen.getByText('Manual Review Required')).toBeInTheDocument();

    const verifyBtn = screen.getByRole('button', { name: /Verify Remediation \(Blocked\)/i });
    expect(verifyBtn).toBeInTheDocument();

    // Click verify on blocked candidate
    await act(async () => {
      fireEvent.click(verifyBtn);
    });

    // Clear nontechnical message explaining that contradictory inventory blocks remediation
    expect(
      await screen.findByText(/contradictory inventory observations detected across manifests and lockfiles block automatic remediation/i)
    ).toBeInTheDocument();

    // No proof conditions table or false success report rendered
    expect(screen.queryByText('Proof-Carrying Verification Results')).not.toBeInTheDocument();

    // Loading state is cleared
    expect(screen.getByRole('button', { name: /Verify Remediation \(Blocked\)/i })).toBeInTheDocument();
  });

  it('handles API returning HTTP 200 with empty results without treating it as successful verification', async () => {
    const { acsaApi } = await import('../api/client');
    vi.spyOn(acsaApi, 'verifyRemediation').mockResolvedValueOnce({
      repository_path: 'tests/fixtures/nodegoat',
      verification_mode: 'MODE_A_SIMULATED',
      total_candidates_verified: 0,
      proven_remediated_count: 0,
      requires_verification_count: 0,
      failed_count: 0,
      results: [],
      warning:
        'No eligible remediation candidate can be verified. Contradictory inventory observations detected across manifests and lockfiles block automatic remediation.',
    });

    render(
      <RemediationView
        repositoryPath="tests/fixtures/nodegoat"
        remediationReport={sampleReport}
        onGenerateRemediation={vi.fn()}
        isLoading={false}
      />
    );

    const verifyBtn = screen.getByRole('button', { name: /Verify Remediation/i });
    await act(async () => {
      fireEvent.click(verifyBtn);
    });

    // Nontechnical message from response warning is shown
    expect(
      await screen.findByText(/Contradictory inventory observations detected across manifests and lockfiles block automatic remediation/i)
    ).toBeInTheDocument();

    // Not treated as successful verification
    expect(screen.queryByText('Proof-Carrying Verification Results')).not.toBeInTheDocument();

    // Loading state cleared
    expect(screen.getByRole('button', { name: /Verify Remediation/i })).toBeInTheDocument();
  });

  it('renders actual backend verification report when valid verification results are returned', async () => {
    const { acsaApi } = await import('../api/client');
    vi.spyOn(acsaApi, 'verifyRemediation').mockResolvedValueOnce({
      repository_path: 'tests/fixtures/nodegoat',
      verification_mode: 'MODE_A_SIMULATED',
      total_candidates_verified: 1,
      proven_remediated_count: 0,
      requires_verification_count: 1,
      failed_count: 0,
      results: [
        {
          candidate: 'cand-1',
          target_component: 'express',
          strategy: 'DIRECT_UPGRADE',
          before: {
            phase: 'before',
            repository_identity: 'tests/fixtures/nodegoat',
            component: 'express',
            version: '4.16.4',
            advisories: ['GHSA-express-1'],
            verdict: 'UNKNOWN',
            reachability_status: 'UNKNOWN',
            reachable_symbols: [],
            exposure_paths: [],
          },
          after: {
            phase: 'after',
            repository_identity: 'tests/fixtures/nodegoat',
            component: 'express',
            version: '4.20.0',
            advisories: [],
            verdict: 'PROVEN_NOT_AFFECTED',
            reachability_status: 'NOT_REACHABLE',
            reachable_symbols: [],
            exposure_paths: [],
          },
          proof_conditions: {
            version_closed: false,
            advisories_closed: true,
            vulnerable_symbol_closed: true,
            exposure_path_closed: false,
            tests_validated: false,
            test_status: 'NOT_EXECUTED',
            test_reason: 'Repository command execution disabled by security policy.',
          },
          evidence: ['ev-proof-1'],
          verification_status: 'REQUIRES_VERIFICATION',
          uncertainty_reason: null,
          missing_evidence: 'Run npm install --package-lock-only to regenerate lockfile.',
          final_verdict: 'UNKNOWN',
        },
      ],
    });

    render(
      <RemediationView
        repositoryPath="tests/fixtures/nodegoat"
        remediationReport={sampleReport}
        onGenerateRemediation={vi.fn()}
        isLoading={false}
      />
    );

    const verifyBtn = screen.getByRole('button', { name: /Verify Remediation/i });
    await act(async () => {
      fireEvent.click(verifyBtn);
    });

    // Renders verification header and counts
    expect(await screen.findByText('Proof-Carrying Verification Results')).toBeInTheDocument();
    expect(screen.getByText(/Verified 1 candidate/i)).toBeInTheDocument();
    expect(screen.getByText('Requires Verification: 1')).toBeInTheDocument();

    // Renders ProofConditionsTable elements
    expect(screen.getByText('Version Closure')).toBeInTheDocument();
    expect(screen.getByText('Advisory Closure')).toBeInTheDocument();
    expect(screen.getByText('Vulnerable Symbol')).toBeInTheDocument();
    expect(screen.getByText('Exposure Path')).toBeInTheDocument();
    expect(screen.getByText('Test Validation')).toBeInTheDocument();

    // Renders missing evidence independently of uncertainty_reason
    expect(
      screen.getByText(/Run npm install --package-lock-only to regenerate lockfile/i)
    ).toBeInTheDocument();

    // Renders supporting evidence chain
    expect(screen.getByText(/Supporting Evidence Chain:/i)).toBeInTheDocument();
    expect(screen.getByText('ev-proof-1')).toBeInTheDocument();

    // Loading state is cleared
    expect(screen.getByRole('button', { name: /Verify Remediation/i })).toBeInTheDocument();
  });

  it('handles API errors visibly and always clears loading state', async () => {
    const { acsaApi } = await import('../api/client');
    vi.spyOn(acsaApi, 'verifyRemediation').mockRejectedValueOnce(
      new Error('Connection timed out to ACSA verification service')
    );

    render(
      <RemediationView
        repositoryPath="tests/fixtures/nodegoat"
        remediationReport={sampleReport}
        onGenerateRemediation={vi.fn()}
        isLoading={false}
      />
    );

    const verifyBtn = screen.getByRole('button', { name: /Verify Remediation/i });
    await act(async () => {
      fireEvent.click(verifyBtn);
    });

    // Error banner is visible
    expect(
      await screen.findByText(/Connection timed out to ACSA verification service/i)
    ).toBeInTheDocument();

    // No proof results displayed
    expect(screen.queryByText('Proof-Carrying Verification Results')).not.toBeInTheDocument();

    // Loading state cleared
    expect(screen.getByRole('button', { name: /Verify Remediation/i })).toBeInTheDocument();
  });
});

describe('ProofConditionsTable Component', () => {
  const sampleProofItem: ProofVerificationItem = {
    candidate: 'cand-12345678',
    target_component: 'express',
    strategy: 'DIRECT_UPGRADE',
    before: {
      phase: 'before',
      repository_identity: 'tests/fixtures/nodegoat',
      component: 'express',
      version: '4.16.4',
      advisories: ['GHSA-express-1', 'GHSA-express-2'],
      verdict: 'UNKNOWN',
      reachability_status: 'UNKNOWN',
      reachable_symbols: ['router.handle'],
      exposure_paths: ['path-1'],
    },
    after: {
      phase: 'after',
      repository_identity: 'tests/fixtures/nodegoat',
      component: 'express',
      version: '4.20.0',
      advisories: [],
      verdict: 'PROVEN_NOT_AFFECTED',
      reachability_status: 'NOT_REACHABLE',
      reachable_symbols: [],
      exposure_paths: [],
    },
    proof_conditions: {
      version_closed: true,
      advisories_closed: true,
      vulnerable_symbol_closed: true,
      exposure_path_closed: false,
      tests_validated: false,
      test_status: 'NOT_EXECUTED',
      test_reason: 'Repository command execution disabled by security policy.',
    },
    evidence: ['ev-proof-1'],
    verification_status: 'REQUIRES_VERIFICATION',
    uncertainty_reason: 'Exposure path severance cannot be verified without lockfile.',
    missing_evidence: 'Regenerated lockfile or runtime probe observation.',
    final_verdict: 'UNKNOWN',
  };

  it('renders before/after snapshots and 5 proof conditions accurately', () => {
    render(<ProofConditionsTable item={sampleProofItem} />);

    // Before/after versions
    expect(screen.getByText('BEFORE REMEDIATION')).toBeInTheDocument();
    expect(screen.getByText('4.16.4')).toBeInTheDocument();
    expect(screen.getByText('AFTER REMEDIATION')).toBeInTheDocument();
    expect(screen.getByText('4.20.0')).toBeInTheDocument();

    // 5 proof conditions
    expect(screen.getByText('Version Closure')).toBeInTheDocument();
    expect(screen.getByText('Advisory Closure')).toBeInTheDocument();
    expect(screen.getByText('Vulnerable Symbol')).toBeInTheDocument();
    expect(screen.getByText('Exposure Path')).toBeInTheDocument();
    expect(screen.getByText('Test Validation')).toBeInTheDocument();

    // Closed vs Unverified states
    expect(screen.getAllByText('✓ CLOSED').length).toBe(3);
    expect(screen.getAllByText('⚠️ UNVERIFIED').length).toBe(1);
    expect(screen.getByText('— NOT EXECUTED')).toBeInTheDocument();

    // Safe execution policy reason
    expect(screen.getByText(/Repository command execution disabled by security policy/i)).toBeInTheDocument();

    // Verification status
    expect(screen.getByRole('status', { name: /Status: REQUIRES_VERIFICATION/i })).toBeInTheDocument();
  });
});
