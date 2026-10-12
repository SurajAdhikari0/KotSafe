/**
 * In-Memory Mock License Server for Development & Testing
 * Copyright (c) 2026 KotSafe Cyber Security Project
 */

import { LicenseApiResponse, LicensePlan } from '../types/license.ts';
import { buildCanonicalPayload, generateSignature } from '../security/signatureVerifier.ts';

export interface MockServerOptions {
  forceError?: 'NETWORK_ERROR' | 'KEY_NOT_FOUND' | 'SEAT_LIMIT' | 'EXPIRED' | 'RATE_LIMITED' | 'REVOKED' | 'TAMPERED_SIGNATURE';
  simulateLatencyMs?: number;
}

export class MockLicenseServer {
  private activeSeatsByDevice: Map<string, string> = new Map();
  private mockOptions: MockServerOptions = {};

  setOptions(options: MockServerOptions) {
    this.mockOptions = options;
  }

  async handleRequest(
    endpoint: '/license/activate' | '/license/validate' | '/license/deactivate',
    body: { key?: string; deviceId?: string; appVersion?: string }
  ): Promise<{ status: number; data: LicenseApiResponse }> {
    if (this.mockOptions.simulateLatencyMs) {
      await new Promise(r => setTimeout(r, this.mockOptions.simulateLatencyMs));
    }

    if (this.mockOptions.forceError === 'NETWORK_ERROR') {
      throw new TypeError('Failed to fetch (simulated network error)');
    }

    const { key = '', deviceId = 'test-device' } = body;

    // Handle Deactivate
    if (endpoint === '/license/deactivate') {
      this.activeSeatsByDevice.delete(deviceId);
      return {
        status: 200,
        data: {
          status: 'invalid',
          plan: 'freemium',
          expiresAt: null,
          seats: { used: 0, max: 0 },
          signature: '',
        },
      };
    }

    // Force explicit error codes
    if (this.mockOptions.forceError) {
      switch (this.mockOptions.forceError) {
        case 'KEY_NOT_FOUND':
          return {
            status: 400,
            data: {
              status: 'invalid',
              plan: 'freemium',
              expiresAt: null,
              seats: { used: 0, max: 0 },
              signature: '',
              errorCode: 'KEY_NOT_FOUND',
            },
          };
        case 'SEAT_LIMIT':
          return {
            status: 400,
            data: {
              status: 'invalid',
              plan: 'pro',
              expiresAt: null,
              seats: { used: 6, max: 6 },
              signature: '',
              errorCode: 'SEAT_LIMIT',
            },
          };
        case 'EXPIRED':
          return {
            status: 400,
            data: {
              status: 'expired',
              plan: 'pro',
              expiresAt: new Date(Date.now() - 86400000).toISOString(),
              seats: { used: 1, max: 6 },
              signature: '',
              errorCode: 'EXPIRED',
            },
          };
        case 'RATE_LIMITED':
          return {
            status: 429,
            data: {
              status: 'invalid',
              plan: 'freemium',
              expiresAt: null,
              seats: { used: 0, max: 0 },
              signature: '',
              errorCode: 'RATE_LIMITED',
            },
          };
        case 'REVOKED':
          return {
            status: 403,
            data: {
              status: 'revoked',
              plan: 'freemium',
              expiresAt: null,
              seats: { used: 0, max: 0 },
              signature: '',
              errorCode: 'REVOKED',
            },
          };
        case 'TAMPERED_SIGNATURE': {
          const resp: LicenseApiResponse = {
            status: 'active',
            plan: 'pro',
            expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
            seats: { used: 1, max: 6 },
            signature: 'TAMPERED_INVALID_SIG_9999999999',
            serverTime: Date.now(),
          };
          return { status: 200, data: resp };
        }
      }
    }

    // Default Success logic
    const isEnterprise = key.includes('ENT');
    const plan: LicensePlan = isEnterprise ? 'enterprise' : 'pro';
    const maxSeats = isEnterprise ? 25 : 6;
    const expiresAt = new Date(Date.now() + 365 * 86400000).toISOString();

    this.activeSeatsByDevice.set(deviceId, key);
    const usedSeats = Math.min(maxSeats, this.activeSeatsByDevice.size || 1);

    const payloadToSign = {
      status: 'active' as const,
      plan,
      expiresAt,
      seats: { used: usedSeats, max: maxSeats },
    };

    const canonical = buildCanonicalPayload(payloadToSign, deviceId);
    const signature = await generateSignature(canonical);

    return {
      status: 200,
      data: {
        ...payloadToSign,
        signature,
        serverTime: Date.now(),
      },
    };
  }
}
