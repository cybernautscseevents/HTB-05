/**
 * Centralized API client for ACSA FastAPI backend.
 * Consumes real endpoints exclusively with structured error handling.
 */

import type {
  HealthResponse,
  ProbeEvaluation,
  ProbeObservation,
  ProbePlanReport,
  ProbeSpecification,
  RemediationReport,
  Verdict,
  VerifyRemediationResponse,
  VulnerabilityScanResult,
} from '../types/api';

export class ApiError extends Error {
  public status: number;
  public detail: string;

  constructor(status: number, detail: string) {
    super(`API Error (${status}): ${detail}`);
    this.name = 'ApiError';
    this.status = status;
    this.detail = detail;
  }
}

const API_BASE = '';

async function postJson<TReq, TRes>(endpoint: string, body: TReq): Promise<TRes> {
  const url = `${API_BASE}${endpoint}`;
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body),
    });

    if (!response.ok) {
      let detail = `Request failed with status ${response.status}`;
      try {
        const errorJson = await response.json();
        if (errorJson && typeof errorJson.detail === 'string') {
          detail = errorJson.detail;
        } else if (errorJson && Array.isArray(errorJson.detail)) {
          detail = errorJson.detail.map((d: { msg?: string }) => d.msg || JSON.stringify(d)).join('; ');
        }
      } catch {
        // Response was not JSON
      }
      throw new ApiError(response.status, detail);
    }

    return (await response.json()) as TRes;
  } catch (err: unknown) {
    if (err instanceof ApiError) {
      throw err;
    }
    const message = err instanceof Error ? err.message : 'Network failure or server unreachable';
    throw new ApiError(0, message);
  }
}

async function getJson<TRes>(endpoint: string): Promise<TRes> {
  const url = `${API_BASE}${endpoint}`;
  try {
    const response = await fetch(url, {
      method: 'GET',
      headers: {
        'Accept': 'application/json',
      },
    });

    if (!response.ok) {
      let detail = `Request failed with status ${response.status}`;
      try {
        const errorJson = await response.json();
        if (errorJson && typeof errorJson.detail === 'string') {
          detail = errorJson.detail;
        }
      } catch {
        // Not JSON
      }
      throw new ApiError(response.status, detail);
    }

    return (await response.json()) as TRes;
  } catch (err: unknown) {
    if (err instanceof ApiError) {
      throw err;
    }
    const message = err instanceof Error ? err.message : 'Network failure or server unreachable';
    throw new ApiError(0, message);
  }
}

export const acsaApi = {
  /** Check backend health status */
  async checkHealth(): Promise<HealthResponse> {
    return getJson<HealthResponse>('/health');
  },

  /** Initiate multi-phase vulnerability, reachability, context, and verdict analysis */
  async scanRepository(repositoryPath: string): Promise<VulnerabilityScanResult> {
    return postJson<{ repository_path: string }, VulnerabilityScanResult>('/scan', {
      repository_path: repositoryPath,
    });
  },

  /** Calculate Minimum-Blast-Radius remediation candidates */
  async remediateRepository(repositoryPath: string): Promise<RemediationReport> {
    return postJson<{ repository_path: string }, RemediationReport>('/remediate', {
      repository_path: repositoryPath,
    });
  },

  /** Verify remediation candidates and generate machine-verifiable proof */
  async verifyRemediation(
    repositoryPath: string,
    candidateId?: string,
    mode: 'MODE_A_SIMULATED' | 'MODE_B_MATERIALIZED' = 'MODE_A_SIMULATED'
  ): Promise<VerifyRemediationResponse> {
    return postJson<
      { repository_path: string; candidate_id?: string | null; mode: string },
      VerifyRemediationResponse
    >('/remediation/verify', {
      repository_path: repositoryPath,
      candidate_id: candidateId ?? null,
      mode,
    });
  },

  /** Generate prioritized dynamic probe specifications for uncertain findings */
  async planProbes(repositoryPath: string): Promise<ProbePlanReport> {
    return postJson<{ repository_path: string }, ProbePlanReport>('/probes/plan', {
      repository_path: repositoryPath,
    });
  },

  /** Safely evaluate an empirical observation against a probe specification */
  async evaluateProbe(
    probe: ProbeSpecification,
    observation: ProbeObservation,
    originalVerdict: Verdict = 'UNKNOWN'
  ): Promise<ProbeEvaluation> {
    return postJson<
      { probe: ProbeSpecification; observation: ProbeObservation; original_verdict: Verdict },
      ProbeEvaluation
    >('/probes/evaluate', {
      probe,
      observation,
      original_verdict: originalVerdict,
    });
  },
};
