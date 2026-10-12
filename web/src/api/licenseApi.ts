/**
 * KotSafe License API Client
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Implements API contract with exponential backoff for network errors,
 * 4xx fast failure (no retries), 429 rate limit parsing, and cryptographic signature verification.
 */

import {
  ActivateRequest,
  DeactivateRequest,
  LicenseApiResponse,
  ValidateRequest,
} from '../types/license.ts';
import { verifyServerSignature } from '../security/signatureVerifier.ts';

export interface ApiClientConfig {
  baseUrl?: string;
  timeoutMs?: number;
  maxRetries?: number;
  appVersion?: string;
}

const DEFAULT_TIMEOUT_MS = 7000;
const DEFAULT_MAX_RETRIES = 3;
const DEFAULT_APP_VERSION = '2.0.0-tactical';

export class LicenseApiError extends Error {
  constructor(
    message: string,
    public statusCode: number,
    public errorCode?: string,
    public retryAfterSeconds?: number,
    public isNetworkError: boolean = false
  ) {
    super(message);
    this.name = 'LicenseApiError';
  }
}

export class LicenseApiClient {
  private baseUrl: string;
  private timeoutMs: number;
  private maxRetries: number;
  private appVersion: string;

  constructor(config: ApiClientConfig = {}) {
    this.baseUrl = config.baseUrl || '';
    this.timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.maxRetries = config.maxRetries ?? DEFAULT_MAX_RETRIES;
    this.appVersion = config.appVersion || DEFAULT_APP_VERSION;
  }

  /**
   * Activates a license key for this device
   */
  async activate(key: string, deviceId: string): Promise<LicenseApiResponse> {
    const payload: ActivateRequest = {
      key,
      deviceId,
      appVersion: this.appVersion,
    };

    const response = await this.requestWithRetry<LicenseApiResponse>(
      '/license/activate',
      payload
    );

    // Cryptographic validation of server response signature
    if (response.status === 'active') {
      const isSignatureValid = await verifyServerSignature(response, deviceId);
      if (!isSignatureValid) {
        throw new LicenseApiError(
          'Security check failed: Server signature mismatch or response tampered.',
          400,
          'TAMPERED_SIGNATURE'
        );
      }
    }

    return response;
  }

  /**
   * Re-validates an existing license key
   */
  async validate(key: string, deviceId: string): Promise<LicenseApiResponse> {
    const payload: ValidateRequest = {
      key,
      deviceId,
    };

    const response = await this.requestWithRetry<LicenseApiResponse>(
      '/license/validate',
      payload
    );

    if (response.status === 'active') {
      const isSignatureValid = await verifyServerSignature(response, deviceId);
      if (!isSignatureValid) {
        throw new LicenseApiError(
          'Security check failed: Server signature mismatch.',
          400,
          'TAMPERED_SIGNATURE'
        );
      }
    }

    return response;
  }

  /**
   * Deactivates license on this device and frees the seat
   */
  async deactivate(key: string, deviceId: string): Promise<LicenseApiResponse> {
    const payload: DeactivateRequest = {
      key,
      deviceId,
    };

    return this.requestWithRetry<LicenseApiResponse>(
      '/license/deactivate',
      payload
    );
  }

  /**
   * Executes HTTP request with exponential backoff for network/5xx errors only.
   * Never retries 4xx client errors.
   */
  private async requestWithRetry<T>(
    endpoint: string,
    body: unknown,
    attempt: number = 0
  ): Promise<T> {
    const url = `${this.baseUrl}${endpoint}`;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), this.timeoutMs);

      const res = await fetch(url, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Accept': 'application/json',
          'X-Client-Version': this.appVersion,
        },
        body: JSON.stringify(body),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      // Handle 429 Too Many Requests
      if (res.status === 429) {
        const retryAfterHeader = res.headers.get('Retry-After');
        const retryAfterSeconds = retryAfterHeader ? parseInt(retryAfterHeader, 10) : 60;
        throw new LicenseApiError(
          'Rate limit reached. Please wait before retrying.',
          429,
          'RATE_LIMITED',
          retryAfterSeconds
        );
      }

      // 4xx Client Errors - Fast fail, NEVER retry
      if (res.status >= 400 && res.status < 500) {
        let errJson: Partial<LicenseApiResponse> = {};
        try {
          errJson = await res.json();
        } catch {
          // ignore
        }
        throw new LicenseApiError(
          this.mapErrorCodeToMessage(errJson.errorCode || 'INVALID'),
          res.status,
          errJson.errorCode || 'INVALID'
        );
      }

      // 5xx Server Errors - Eligible for retry
      if (res.status >= 500) {
        throw new LicenseApiError(
          `Server returned error ${res.status}`,
          res.status,
          'SERVER_ERROR',
          undefined,
          true
        );
      }

      return (await res.json()) as T;
    } catch (err: unknown) {
      if (err instanceof LicenseApiError && !err.isNetworkError) {
        // Fast fail on client error (4xx)
        throw err;
      }

      const isNetwork =
        err instanceof TypeError ||
        (err instanceof Error && err.name === 'AbortError') ||
        (err instanceof LicenseApiError && err.isNetworkError);

      if (isNetwork && attempt < this.maxRetries) {
        const delayMs = Math.pow(2, attempt) * 1000; // 1s, 2s, 4s
        await new Promise(resolve => setTimeout(resolve, delayMs));
        return this.requestWithRetry<T>(endpoint, body, attempt + 1);
      }

      throw new LicenseApiError(
        'Unable to connect to license verification server.',
        0,
        'NETWORK_ERROR',
        undefined,
        true
      );
    }
  }

  private mapErrorCodeToMessage(code: string): string {
    switch (code) {
      case 'KEY_NOT_FOUND':
        return 'License key was not found or is invalid.';
      case 'SEAT_LIMIT':
        return 'This license key has reached its maximum device limit.';
      case 'EXPIRED':
        return 'This license key has expired. Please renew your subscription.';
      case 'REVOKED':
        return 'This license key has been revoked by the administrator.';
      case 'RATE_LIMITED':
        return 'Too many activation attempts. Please wait a moment.';
      case 'TAMPERED_SIGNATURE':
        return 'Cryptographic signature mismatch. The server response may have been modified.';
      default:
        return 'Activation failed. Please verify your key.';
    }
  }
}
