/**
 * KotSafe License Core Service (Singleton)
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Implements:
 * - Single source of truth license state machine
 * - Synchronous hydration on load (no state flash)
 * - Automatic background re-validation (on startup + every 24h)
 * - 7-day offline grace period handling
 * - Multi-tab real-time state synchronization
 * - Feature gating service
 * - Rate-limit enforcement
 */

import {
  CachedLicenseData,
  FeatureKey,
  LicenseRecord,
  LicenseState,
} from '../types/license.ts';
import {
  calculateDaysLeft,
  calculateGracePeriod,
  isLicenseEntitled,
  transitionLicenseState,
} from '../core/licenseStateMachine.ts';
import {
  checkRateLimit,
  clearLicenseFromStorage,
  getOrCreateDeviceId,
  getSynchronousCachedLicense,
  recordActivationAttempt,
  saveLicenseToStorage,
} from '../security/secureStorage.ts';
import { LicenseApiClient, LicenseApiError } from '../api/licenseApi.ts';
import { tabSyncManager } from './tabSync.ts';
import { maskKey, validateKeyFormat } from '../core/keyValidator.ts';

const REVALIDATION_INTERVAL_MS = 24 * 60 * 60 * 1000; // 24 hours

export type StateChangeListener = (
  state: LicenseState,
  record: LicenseRecord | null
) => void;

export class LicenseService {
  private currentState: LicenseState = 'UNLICENSED';
  private currentRecord: LicenseRecord | null = null;
  private apiClient: LicenseApiClient;
  private listeners: Set<StateChangeListener> = new Set();
  private backgroundTimer: ReturnType<typeof setInterval> | null = null;
  private liveExpiryTimer: ReturnType<typeof setInterval> | null = null;
  private tabSyncUnsub: (() => void) | null = null;
  private isVerifying: boolean = false;

  constructor(apiClient?: LicenseApiClient) {
    this.apiClient = apiClient || new LicenseApiClient();
    this.hydrateSynchronously();
    this.setupTabSync();
    this.scheduleBackgroundValidation();
    this.scheduleLiveExpiryCheck();
  }

  /**
   * Hydrates state synchronously from secure storage on load
   */
  private hydrateSynchronously(): void {
    const cached = getSynchronousCachedLicense();
    if (!cached || !cached.record) {
      this.currentState = 'UNLICENSED';
      this.currentRecord = null;
      return;
    }

    const record = cached.record;
    const now = Date.now();

    // Check expiration
    if (record.expiresAt && new Date(record.expiresAt).getTime() <= now) {
      this.currentState = 'EXPIRED';
      this.currentRecord = record;
      return;
    }

    // Check grace period based on last verified time
    const lastVerifiedEpoch = new Date(record.lastVerifiedAt).getTime();
    const graceStatus = calculateGracePeriod(lastVerifiedEpoch, now);

    if (cached.state === 'GRACE_PERIOD') {
      if (graceStatus.isWithinGrace) {
        this.currentState = 'GRACE_PERIOD';
        this.currentRecord = record;
      } else {
        this.currentState = 'UNLICENSED';
        this.currentRecord = null;
        clearLicenseFromStorage();
      }
      return;
    }

    if (cached.state === 'ACTIVE') {
      // If server check has been older than 7 days, check grace
      if (!graceStatus.isWithinGrace) {
        this.currentState = 'UNLICENSED';
        this.currentRecord = null;
        clearLicenseFromStorage();
      } else if (now - lastVerifiedEpoch > 24 * 60 * 60 * 1000) {
        // More than 24h offline, tentatively mark active but revalidate immediately
        this.currentState = 'ACTIVE';
        this.currentRecord = record;
        setTimeout(() => this.revalidate(), 100);
      } else {
        this.currentState = 'ACTIVE';
        this.currentRecord = record;
      }
      return;
    }

    this.currentState = cached.state;
    this.currentRecord = record;
  }

  /**
   * Multi-tab real-time sync subscription
   */
  private setupTabSync(): void {
    this.tabSyncUnsub = tabSyncManager.subscribe(msg => {
      if (msg.type === 'LICENSE_DEACTIVATED') {
        this.currentState = 'UNLICENSED';
        this.currentRecord = null;
        this.notify();
      } else if (msg.type === 'LICENSE_ACTIVATED' || msg.type === 'LICENSE_UPDATED') {
        this.currentState = msg.payload.state;
        this.currentRecord = msg.payload.record;
        this.notify();
      }
    });
  }

  /**
   * Activates a license key
   */
  async activate(rawKey: string): Promise<{ success: boolean; error?: string }> {
    if (this.isVerifying) {
      return { success: false, error: 'Activation already in progress.' };
    }

    // 1. Client-side Format Validation
    const validation = validateKeyFormat(rawKey);
    if (!validation.isValid) {
      this.currentState = transitionLicenseState(this.currentState, {
        type: 'VERIFY_INVALID',
      });
      this.notify();
      return { success: false, error: validation.error };
    }

    // 2. Client-side Rate Limit check
    const rateLimit = checkRateLimit();
    if (rateLimit.isRateLimited) {
      return {
        success: false,
        error: `Too many activation attempts. Cooldown: ${rateLimit.cooldownRemainingSeconds}s remaining.`,
      };
    }

    recordActivationAttempt();

    const normalizedKey = validation.normalized;
    const deviceId = getOrCreateDeviceId();

    this.isVerifying = true;
    this.currentState = transitionLicenseState(this.currentState, {
      type: 'VERIFY_START',
    });
    this.notify();

    try {
      const response = await this.apiClient.activate(normalizedKey, deviceId);
      this.isVerifying = false;

      if (response.status === 'active') {
        const record: LicenseRecord = {
          key: normalizedKey,
          status: 'active',
          plan: response.plan,
          expiresAt: response.expiresAt,
          activatedAt: new Date().toISOString(),
          lastVerifiedAt: new Date().toISOString(),
          seats: response.seats,
          signature: response.signature,
          deviceId,
        };

        this.currentRecord = record;
        this.currentState = transitionLicenseState(this.currentState, {
          type: 'VERIFY_SUCCESS',
        });

        // Persist securely
        const cacheData: CachedLicenseData = {
          record,
          state: 'ACTIVE',
          lastCheckedTime: Date.now(),
          storedAt: Date.now(),
        };
        saveLicenseToStorage(cacheData);

        // Sync across other open tabs
        tabSyncManager.broadcast({
          type: 'LICENSE_ACTIVATED',
          payload: cacheData,
        });

        this.scheduleLiveExpiryCheck();
        this.notify();
        return { success: true };
      }

      // Handle server returned non-active status
      if (response.status === 'expired') {
        this.currentState = transitionLicenseState(this.currentState, {
          type: 'VERIFY_EXPIRED',
        });
        this.notify();
        return { success: false, error: 'License key has expired.' };
      }

      this.currentState = transitionLicenseState(this.currentState, {
        type: 'VERIFY_INVALID',
      });
      this.notify();
      return { success: false, error: 'License key is invalid.' };
    } catch (err: unknown) {
      this.isVerifying = false;

      if (err instanceof LicenseApiError) {
        if (err.errorCode === 'SEAT_LIMIT') {
          this.currentState = transitionLicenseState(this.currentState, {
            type: 'VERIFY_INVALID',
          });
          this.notify();
          return { success: false, error: err.message };
        }
        if (err.errorCode === 'EXPIRED') {
          this.currentState = transitionLicenseState(this.currentState, {
            type: 'VERIFY_EXPIRED',
          });
          this.notify();
          return { success: false, error: err.message };
        }
        if (err.errorCode === 'REVOKED' || err.errorCode === 'KEY_NOT_FOUND') {
          this.currentState = transitionLicenseState(this.currentState, {
            type: 'VERIFY_INVALID',
          });
          this.notify();
          return { success: false, error: err.message };
        }
        if (err.isNetworkError) {
          this.currentState = transitionLicenseState(this.currentState, {
            type: 'VERIFY_ERROR',
          });
          this.notify();
          return { success: false, error: err.message };
        }
      }

      this.currentState = transitionLicenseState(this.currentState, {
        type: 'VERIFY_ERROR',
      });
      this.notify();
      return {
        success: false,
        error:
          err instanceof Error
            ? err.message
            : 'Activation failed due to an unexpected error.',
      };
    }
  }

  /**
   * Re-validates the current license with the server
   */
  async revalidate(): Promise<{ success: boolean; error?: string }> {
    if (!this.currentRecord || !this.currentRecord.key) {
      return { success: false, error: 'No stored license to revalidate.' };
    }

    if (this.isVerifying) {
      return { success: false, error: 'Validation already in progress.' };
    }

    const key = this.currentRecord.key;
    const deviceId = this.currentRecord.deviceId || getOrCreateDeviceId();
    const lastVerifiedEpoch = new Date(this.currentRecord.lastVerifiedAt).getTime();

    this.isVerifying = true;
    this.currentState = transitionLicenseState(this.currentState, {
      type: 'VERIFY_START',
    });
    this.notify();

    try {
      const response = await this.apiClient.validate(key, deviceId);
      this.isVerifying = false;

      if (response.status === 'active') {
        const updatedRecord: LicenseRecord = {
          ...this.currentRecord,
          status: 'active',
          plan: response.plan,
          expiresAt: response.expiresAt,
          seats: response.seats,
          signature: response.signature,
          lastVerifiedAt: new Date().toISOString(),
        };

        this.currentRecord = updatedRecord;
        this.currentState = transitionLicenseState(this.currentState, {
          type: 'VERIFY_SUCCESS',
        });

        const cacheData: CachedLicenseData = {
          record: updatedRecord,
          state: 'ACTIVE',
          lastCheckedTime: Date.now(),
          storedAt: Date.now(),
        };
        saveLicenseToStorage(cacheData);

        tabSyncManager.broadcast({
          type: 'LICENSE_UPDATED',
          payload: cacheData,
        });

        this.notify();
        return { success: true };
      }

      if (response.status === 'expired') {
        this.currentState = transitionLicenseState(this.currentState, {
          type: 'VERIFY_EXPIRED',
        });
        clearLicenseFromStorage();
        this.notify();
        return { success: false, error: 'License key has expired.' };
      }

      if (response.status === 'revoked' || response.status === 'invalid') {
        this.currentState = transitionLicenseState(this.currentState, {
          type: 'VERIFY_INVALID',
        });
        clearLicenseFromStorage();
        this.notify();
        return { success: false, error: 'License key is revoked or invalid.' };
      }

      return { success: false };
    } catch (err: unknown) {
      this.isVerifying = false;

      // Handle Server Unreachable / Network Error: Offline Grace Period
      const isNetwork =
        (err instanceof LicenseApiError && err.isNetworkError) ||
        (err instanceof Error &&
          (err.name === 'AbortError' ||
            err.name === 'TypeError' ||
            // @ts-expect-error duck typing
            err.isNetworkError === true));

      if (isNetwork) {
        const now = Date.now();
        const grace = calculateGracePeriod(lastVerifiedEpoch, now);

        if (grace.isWithinGrace) {
          this.currentState = transitionLicenseState(this.currentState, {
            type: 'SERVER_UNREACHABLE',
            lastVerifiedEpoch,
            nowEpoch: now,
          });

          // Update storage with GRACE_PERIOD state
          const cacheData: CachedLicenseData = {
            record: this.currentRecord,
            state: 'GRACE_PERIOD',
            lastCheckedTime: now,
            storedAt: Date.now(),
          };
          saveLicenseToStorage(cacheData);
          this.notify();
          return {
            success: true,
            error: `Server unreachable. License valid offline in grace period (${grace.daysRemaining} days left).`,
          };
        } else {
          // Grace period exceeded (> 7 days unreachable)
          this.currentState = transitionLicenseState(this.currentState, {
            type: 'GRACE_EXPIRED',
          });
          this.currentRecord = null;
          clearLicenseFromStorage();
          this.notify();
          return {
            success: false,
            error: 'Grace period has expired. Please connect to the internet to verify your license.',
          };
        }
      }

      this.currentState = transitionLicenseState(this.currentState, {
        type: 'VERIFY_ERROR',
      });
      this.notify();
      return {
        success: false,
        error: err instanceof Error ? err.message : 'Validation failed.',
      };
    }
  }

  /**
   * Deactivates the license on this device
   */
  async deactivate(): Promise<{ success: boolean; error?: string }> {
    if (!this.currentRecord || !this.currentRecord.key) {
      this.currentState = 'UNLICENSED';
      this.currentRecord = null;
      clearLicenseFromStorage();
      this.notify();
      return { success: true };
    }

    const key = this.currentRecord.key;
    const deviceId = this.currentRecord.deviceId || getOrCreateDeviceId();

    this.currentState = transitionLicenseState(this.currentState, {
      type: 'DEACTIVATE_START',
    });
    this.notify();

    try {
      await this.apiClient.deactivate(key, deviceId);
    } catch (err) {
      console.warn('[KotSafe License] Remote deactivation failed, proceeding with local revocation:', err);
    }

    this.currentState = transitionLicenseState(this.currentState, {
      type: 'DEACTIVATE_SUCCESS',
    });
    this.currentRecord = null;
    clearLicenseFromStorage();

    tabSyncManager.broadcast({
      type: 'LICENSE_DEACTIVATED',
    });

    this.notify();
    return { success: true };
  }

  /**
   * Gating check for paid features across the application
   */
  canAccessFeature(feature: FeatureKey): boolean {
    if (feature === 'standard_capture') {
      return true;
    }

    if (!isLicenseEntitled(this.currentState) || !this.currentRecord) {
      return false;
    }

    const plan = this.currentRecord.plan;
    if (plan === 'enterprise') {
      return true;
    }
    if (plan === 'pro') {
      return feature !== 'zero_latency_mesh'; // enterprise only
    }

    return false;
  }

  /**
   * Sets up background revalidation check every 24h
   */
  private scheduleBackgroundValidation(): void {
    if (this.backgroundTimer) {
      clearInterval(this.backgroundTimer);
    }
    this.backgroundTimer = setInterval(() => {
      if (isLicenseEntitled(this.currentState)) {
        this.revalidate();
      }
    }, REVALIDATION_INTERVAL_MS);
  }

  /**
   * Live expiration check while the application remains open
   */
  private scheduleLiveExpiryCheck(): void {
    if (this.liveExpiryTimer) {
      clearInterval(this.liveExpiryTimer);
    }

    this.liveExpiryTimer = setInterval(() => {
      if (
        isLicenseEntitled(this.currentState) &&
        this.currentRecord &&
        this.currentRecord.expiresAt
      ) {
        const { isExpired } = calculateDaysLeft(this.currentRecord.expiresAt);
        if (isExpired) {
          this.currentState = transitionLicenseState(this.currentState, {
            type: 'VERIFY_EXPIRED',
          });
          clearLicenseFromStorage();
          this.notify();
        }
      }
    }, 60 * 1000); // Check every minute
  }

  // Getters
  public getState(): LicenseState {
    return this.currentState;
  }

  public getRecord(): LicenseRecord | null {
    return this.currentRecord;
  }

  public getMaskedKey(): string {
    return maskKey(this.currentRecord?.key);
  }

  public isLicensed(): boolean {
    return isLicenseEntitled(this.currentState);
  }

  public subscribe(listener: StateChangeListener): () => void {
    this.listeners.add(listener);
    return () => this.listeners.delete(listener);
  }

  private notify(): void {
    this.listeners.forEach(cb => {
      try {
        cb(this.currentState, this.currentRecord);
      } catch (err) {
        console.error('[LicenseService] Listener error:', err);
      }
    });
  }

  public destroy(): void {
    if (this.backgroundTimer) clearInterval(this.backgroundTimer);
    if (this.liveExpiryTimer) clearInterval(this.liveExpiryTimer);
    if (this.tabSyncUnsub) this.tabSyncUnsub();
    this.listeners.clear();
  }
}

// Global Singleton Instance
export const licenseService = new LicenseService();
