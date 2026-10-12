import { describe, it, expect, vi, beforeEach } from 'vitest';
import { LicenseApiClient, LicenseApiError } from '../src/api/licenseApi.ts';
import { buildCanonicalPayload, generateSignature } from '../src/security/signatureVerifier.ts';

describe('License API Client', () => {
  let client: LicenseApiClient;
  const deviceId = 'test-device-uuid-1';

  beforeEach(() => {
    vi.restoreAllMocks();
    client = new LicenseApiClient({
      baseUrl: 'http://localhost:8080',
      timeoutMs: 1000,
      maxRetries: 2,
    });
  });

  it('activates key and verifies signature successfully', async () => {
    const rawPayload = {
      status: 'active' as const,
      plan: 'pro' as const,
      expiresAt: '2027-10-12T00:00:00.000Z',
      seats: { used: 1, max: 6 },
    };
    const signature = await generateSignature(buildCanonicalPayload(rawPayload, deviceId));

    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 200,
      json: async () => ({ ...rawPayload, signature, serverTime: Date.now() }),
    });

    const res = await client.activate('KOT-PRO-ABCD1234-EF56', deviceId);
    expect(res.status).toBe('active');
    expect(res.plan).toBe('pro');
    expect(res.signature).toBe(signature);
  });

  it('fails fast on 4xx client errors without retrying', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      status: 400,
      json: async () => ({
        status: 'invalid',
        errorCode: 'KEY_NOT_FOUND',
      }),
    });
    globalThis.fetch = fetchMock;

    await expect(client.activate('KOT-PRO-INVALID1-0000', deviceId)).rejects.toThrowError(
      LicenseApiError
    );

    // Fast-fail: Exactly 1 call, no retries on 4xx
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it('handles 429 Rate Limit with Retry-After header', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 429,
      headers: {
        get: (h: string) => (h.toLowerCase() === 'retry-after' ? '45' : null),
      },
      json: async () => ({ errorCode: 'RATE_LIMITED' }),
    });

    try {
      await client.activate('KOT-PRO-ABCD1234-EF56', deviceId);
      expect.fail('Should have thrown');
    } catch (err) {
      expect(err).toBeInstanceOf(LicenseApiError);
      const apiErr = err as LicenseApiError;
      expect(apiErr.statusCode).toBe(429);
      expect(apiErr.errorCode).toBe('RATE_LIMITED');
      expect(apiErr.retryAfterSeconds).toBe(45);
    }
  });

  it('retries on network failure with exponential backoff', async () => {
    const fetchMock = vi.fn().mockRejectedValue(new TypeError('Failed to fetch'));
    globalThis.fetch = fetchMock;

    await expect(client.activate('KOT-PRO-ABCD1234-EF56', deviceId)).rejects.toThrowError(
      'Unable to connect to license verification server'
    );

    // 1 initial attempt + 2 retries = 3 calls
    expect(fetchMock).toHaveBeenCalledTimes(3);
  });

  it('rejects tampered server signature', async () => {
    globalThis.fetch = vi.fn().mockResolvedValue({
      status: 200,
      json: async () => ({
        status: 'active',
        plan: 'pro',
        expiresAt: '2027-10-12T00:00:00.000Z',
        seats: { used: 1, max: 6 },
        signature: 'INVALID_TAMPERED_SIG',
      }),
    });

    await expect(client.activate('KOT-PRO-ABCD1234-EF56', deviceId)).rejects.toThrow(
      'Server signature mismatch'
    );
  });
});
