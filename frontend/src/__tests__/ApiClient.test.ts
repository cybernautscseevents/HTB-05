import { describe, it, expect, vi, beforeEach } from 'vitest';
import { acsaApi, ApiError } from '../api/client';

describe('ApiClient and ApiError', () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it('correctly constructs ApiError with status and detail', () => {
    const error = new ApiError(404, 'Repository not found');
    expect(error.name).toBe('ApiError');
    expect(error.status).toBe(404);
    expect(error.detail).toBe('Repository not found');
    expect(error.message).toContain('404');
    expect(error.message).toContain('Repository not found');
  });

  it('handles successful checkHealth request', async () => {
    const mockResponse = { status: 'ok', service: 'acsa-api' };
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: true,
        json: async () => mockResponse,
      })
    );

    const res = await acsaApi.checkHealth();
    expect(res).toEqual(mockResponse);
  });

  it('handles HTTP 400 bad request error with detail message from FastAPI', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue({
        ok: false,
        status: 400,
        json: async () => ({ detail: 'Path security violation: Directory traversal detected' }),
      })
    );

    await expect(acsaApi.scanRepository('../../../etc')).rejects.toThrow(ApiError);
    await expect(acsaApi.scanRepository('../../../etc')).rejects.toMatchObject({
      status: 400,
      detail: 'Path security violation: Directory traversal detected',
    });
  });

  it('handles network failure gracefully without crashing', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockRejectedValue(new Error('Failed to fetch'))
    );

    await expect(acsaApi.checkHealth()).rejects.toThrow(ApiError);
    await expect(acsaApi.checkHealth()).rejects.toMatchObject({
      status: 0,
      detail: 'Failed to fetch',
    });
  });
});
