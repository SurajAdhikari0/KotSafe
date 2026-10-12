import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { LicenseService } from '../src/services/licenseService.ts';
import { LicenseApiClient } from '../src/api/licenseApi.ts';
import { clearLicenseFromStorage, saveLicenseToStorage } from '../src/security/secureStorage.ts';
import { buildCanonicalPayload, generateSignature } from '../src/security/signatureVerifier.ts';
import { CachedLicenseData } from '../src/types/license.ts';

describe('License Service Core Logic', () => {
  let service: LicenseService;
  let mockApiClient: LicenseApiClient;

  beforeEach(() => {
    localStorage.clear();
    clearLicenseFromStorage();

    mockApiClient = new LicenseApiClient({ baseUrl: 'http://localhost:8080' });
    service = new LicenseService(mockApiClient);
  });

  afterEach(() => {
    service.destroy();
  });

  it('initializes with UNLICENSED when storage is empty', () => {
    expect(service.getState()).toBe('UNLICENSED');
    expect(service.isLicensed()).toBe(false);
  });

  it('hydrates synchronously from cached record without flashing UNLICENSED', () => {
    const cached: CachedLicenseData = {
      record: {
        key: 'KOT-PRO-ABCD1234-EF56',
        status: 'active',
        plan: 'pro',
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
        activatedAt: new Date().toISOString(),
        lastVerifiedAt: new Date().toISOString(),
        seats: { used: 1, max: 6 },
        signature: 'SIG123',
        deviceId: 'device-1',
      },
      state: 'ACTIVE',
      lastCheckedTime: Date.now(),
      storedAt: Date.now(),
    };
    saveLicenseToStorage(cached);

    // Create a new service instance to test startup hydration
    const freshService = new LicenseService(mockApiClient);
    expect(freshService.getState()).toBe('ACTIVE');
    expect(freshService.isLicensed()).toBe(true);
    expect(freshService.getMaskedKey()).toBe('****-****-****-EF56');
    freshService.destroy();
  });

  it('activates key and updates state to ACTIVE', async () => {
    const signature = await generateSignature(
      buildCanonicalPayload(
        {
          status: 'active',
          plan: 'pro',
          expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
          seats: { used: 1, max: 6 },
        },
        'device-1'
      )
    );

    vi.spyOn(mockApiClient, 'activate').mockResolvedValue({
      status: 'active',
      plan: 'pro',
      expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      seats: { used: 1, max: 6 },
      signature,
      serverTime: Date.now(),
    });

    const result = await service.activate('KOT-PRO-ABCD1234-EF56');
    expect(result.success).toBe(true);
    expect(service.getState()).toBe('ACTIVE');
    expect(service.isLicensed()).toBe(true);
    expect(service.getMaskedKey()).toBe('****-****-****-EF56');
  });

  it('falls back to GRACE_PERIOD when server is unreachable within 7 days', async () => {
    // Set up active state with last verified 2 days ago
    const cached: CachedLicenseData = {
      record: {
        key: 'KOT-PRO-ABCD1234-EF56',
        status: 'active',
        plan: 'pro',
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
        activatedAt: new Date().toISOString(),
        lastVerifiedAt: new Date(Date.now() - 2 * 86400000).toISOString(),
        seats: { used: 1, max: 6 },
        signature: 'SIG123',
        deviceId: 'device-1',
      },
      state: 'ACTIVE',
      lastCheckedTime: Date.now(),
      storedAt: Date.now(),
    };
    saveLicenseToStorage(cached);
    const graceService = new LicenseService(mockApiClient);

    // Mock validate network failure
    const netErr = new Error('Network error');
    // @ts-expect-error test mock
    netErr.isNetworkError = true;
    vi.spyOn(mockApiClient, 'validate').mockRejectedValue(netErr);

    const reval = await graceService.revalidate();
    expect(reval.success).toBe(true);
    expect(graceService.getState()).toBe('GRACE_PERIOD');
    expect(graceService.isLicensed()).toBe(true);
    graceService.destroy();
  });

  it('deactivates device and restores state to UNLICENSED', async () => {
    const cached: CachedLicenseData = {
      record: {
        key: 'KOT-PRO-ABCD1234-EF56',
        status: 'active',
        plan: 'pro',
        expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
        activatedAt: new Date().toISOString(),
        lastVerifiedAt: new Date().toISOString(),
        seats: { used: 1, max: 6 },
        signature: 'SIG123',
        deviceId: 'device-1',
      },
      state: 'ACTIVE',
      lastCheckedTime: Date.now(),
      storedAt: Date.now(),
    };
    saveLicenseToStorage(cached);

    const activeService = new LicenseService(mockApiClient);
    expect(activeService.getState()).toBe('ACTIVE');

    vi.spyOn(mockApiClient, 'deactivate').mockResolvedValue({
      status: 'invalid',
      plan: 'freemium',
      expiresAt: null,
      seats: { used: 0, max: 0 },
      signature: '',
    });

    const deact = await activeService.deactivate();
    expect(deact.success).toBe(true);
    expect(activeService.getState()).toBe('UNLICENSED');
    expect(activeService.isLicensed()).toBe(false);
    expect(activeService.getRecord()).toBeNull();
    activeService.destroy();
  });

  it('enforces feature gating for free vs pro tiers', () => {
    // Unlicensed: only standard_capture allowed
    expect(service.canAccessFeature('standard_capture')).toBe(true);
    expect(service.canAccessFeature('p2p_multi_device')).toBe(false);
    expect(service.canAccessFeature('ai_autonomous_guard')).toBe(false);
    expect(service.canAccessFeature('yara_memory_scan')).toBe(false);
  });
});
