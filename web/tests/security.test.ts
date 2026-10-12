import { describe, it, expect, beforeEach } from 'vitest';
import {
  buildCanonicalPayload,
  generateSignature,
  verifyServerSignature,
} from '../src/security/signatureVerifier.ts';
import {
  getOrCreateDeviceId,
  saveLicenseToStorage,
  getSynchronousCachedLicense,
  clearLicenseFromStorage,
  checkRateLimit,
  recordActivationAttempt,
} from '../src/security/secureStorage.ts';
import { CachedLicenseData, LicenseApiResponse } from '../src/types/license.ts';

describe('Security & Cryptography', () => {
  beforeEach(() => {
    localStorage.clear();
    clearLicenseFromStorage();
  });

  describe('Signature Verification', () => {
    it('verifies legitimate server signature', async () => {
      const deviceId = 'device-abc-123';
      const response: LicenseApiResponse = {
        status: 'active',
        plan: 'pro',
        expiresAt: '2027-10-12T00:00:00.000Z',
        seats: { used: 1, max: 6 },
        signature: '',
      };

      const canonical = buildCanonicalPayload(response, deviceId);
      const validSig = await generateSignature(canonical);
      response.signature = validSig;

      const isValid = await verifyServerSignature(response, deviceId);
      expect(isValid).toBe(true);
    });

    it('rejects tampered server signature', async () => {
      const deviceId = 'device-abc-123';
      const response: LicenseApiResponse = {
        status: 'active',
        plan: 'pro',
        expiresAt: '2027-10-12T00:00:00.000Z',
        seats: { used: 1, max: 6 },
        signature: 'TAMPERED_FAKE_SIGNATURE_00000',
      };

      const isValid = await verifyServerSignature(response, deviceId);
      expect(isValid).toBe(false);
    });

    it('rejects response if plan was tampered after signing', async () => {
      const deviceId = 'device-abc-123';
      const original: LicenseApiResponse = {
        status: 'active',
        plan: 'pro',
        expiresAt: '2027-10-12T00:00:00.000Z',
        seats: { used: 1, max: 6 },
        signature: '',
      };

      const canonical = buildCanonicalPayload(original, deviceId);
      const validSig = await generateSignature(canonical);

      // Attacker attempts to change plan to enterprise
      const tampered: LicenseApiResponse = {
        ...original,
        plan: 'enterprise',
        signature: validSig,
      };

      const isValid = await verifyServerSignature(tampered, deviceId);
      expect(isValid).toBe(false);
    });
  });

  describe('Secure Encrypted Storage', () => {
    it('generates and persists a stable deviceId', () => {
      const id1 = getOrCreateDeviceId();
      expect(id1).toBeDefined();
      expect(id1.startsWith('kot-')).toBe(true);

      const id2 = getOrCreateDeviceId();
      expect(id2).toBe(id1);
    });

    it('saves and synchronously hydrates cached license without storing plain key', () => {
      const testCache: CachedLicenseData = {
        record: {
          key: 'KOT-PRO-ABCD1234-EF56',
          status: 'active',
          plan: 'pro',
          expiresAt: '2027-10-12T00:00:00.000Z',
          activatedAt: '2026-10-12T00:00:00.000Z',
          lastVerifiedAt: '2026-10-12T00:00:00.000Z',
          seats: { used: 1, max: 6 },
          signature: 'SIG123456',
          deviceId: getOrCreateDeviceId(),
        },
        state: 'ACTIVE',
        lastCheckedTime: Date.now(),
        storedAt: Date.now(),
      };

      saveLicenseToStorage(testCache);

      // Verify plain key does NOT exist in raw localStorage
      const rawStored = localStorage.getItem('kotsafe_sec_license_v2');
      expect(rawStored).toBeDefined();
      expect(rawStored).not.toContain('KOT-PRO-ABCD1234-EF56');

      // Hydrate synchronously
      const hydrated = getSynchronousCachedLicense();
      expect(hydrated).toBeDefined();
      expect(hydrated?.state).toBe('ACTIVE');
      expect(hydrated?.record?.key).toBe('KOT-PRO-ABCD1234-EF56');
    });

    it('clears storage completely on license removal', () => {
      const testCache: CachedLicenseData = {
        record: null,
        state: 'UNLICENSED',
        lastCheckedTime: Date.now(),
        storedAt: Date.now(),
      };
      saveLicenseToStorage(testCache);
      expect(getSynchronousCachedLicense()).toBeDefined();

      clearLicenseFromStorage();
      expect(getSynchronousCachedLicense()).toBeNull();
    });
  });

  describe('Rate Limiting', () => {
    it('enforces 5 attempts per minute cooldown', () => {
      expect(checkRateLimit().isRateLimited).toBe(false);

      for (let i = 0; i < 5; i++) {
        recordActivationAttempt();
      }

      const limit = checkRateLimit();
      expect(limit.isRateLimited).toBe(true);
      expect(limit.cooldownRemainingSeconds).toBeGreaterThan(0);
      expect(limit.cooldownRemainingSeconds).toBeLessThanOrEqual(60);
    });
  });
});
