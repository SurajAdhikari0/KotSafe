/**
 * KotSafe License State Machine
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Explicit State Machine (Single Source of Truth):
 *
 *   UNLICENSED (Freemium) -> VERIFYING -> ACTIVE
 *                                      -> INVALID
 *                                      -> EXPIRED
 *                                      -> ERROR (network/server)
 *   ACTIVE -> GRACE_PERIOD (server unreachable <= 7 days)
 *   ACTIVE -> DEACTIVATING -> UNLICENSED
 */

import { LicenseState, StateBadgeConfig } from '../types/license.ts';

export const GRACE_PERIOD_MS = 7 * 24 * 60 * 60 * 1000; // 7 days in milliseconds

export type LicenseEvent =
  | { type: 'VERIFY_START' }
  | { type: 'VERIFY_SUCCESS' }
  | { type: 'VERIFY_INVALID' }
  | { type: 'VERIFY_EXPIRED' }
  | { type: 'VERIFY_ERROR'; isGraceEligible?: boolean }
  | { type: 'SERVER_UNREACHABLE'; lastVerifiedEpoch: number; nowEpoch?: number }
  | { type: 'GRACE_EXPIRED' }
  | { type: 'DEACTIVATE_START' }
  | { type: 'DEACTIVATE_SUCCESS' }
  | { type: 'DEACTIVATE_FAIL' }
  | { type: 'RESET_TO_UNLICENSED' };

/**
 * Pure transition function for the license state machine
 */
export function transitionLicenseState(
  currentState: LicenseState,
  event: LicenseEvent
): LicenseState {
  switch (currentState) {
    case 'UNLICENSED':
    case 'INVALID':
    case 'EXPIRED':
    case 'ERROR': {
      if (event.type === 'VERIFY_START') {
        return 'VERIFYING';
      }
      if (event.type === 'RESET_TO_UNLICENSED') {
        return 'UNLICENSED';
      }
      return currentState;
    }

    case 'VERIFYING': {
      switch (event.type) {
        case 'VERIFY_SUCCESS':
          return 'ACTIVE';
        case 'VERIFY_INVALID':
          return 'INVALID';
        case 'VERIFY_EXPIRED':
          return 'EXPIRED';
        case 'VERIFY_ERROR':
          return event.isGraceEligible ? 'GRACE_PERIOD' : 'ERROR';
        case 'SERVER_UNREACHABLE': {
          const now = event.nowEpoch ?? Date.now();
          const elapsed = now - event.lastVerifiedEpoch;
          return elapsed <= GRACE_PERIOD_MS ? 'GRACE_PERIOD' : 'UNLICENSED';
        }
        case 'RESET_TO_UNLICENSED':
          return 'UNLICENSED';
        default:
          return currentState;
      }
    }

    case 'ACTIVE': {
      switch (event.type) {
        case 'VERIFY_START':
          return 'VERIFYING';
        case 'SERVER_UNREACHABLE': {
          const now = event.nowEpoch ?? Date.now();
          const elapsed = now - event.lastVerifiedEpoch;
          return elapsed <= GRACE_PERIOD_MS ? 'GRACE_PERIOD' : 'UNLICENSED';
        }
        case 'VERIFY_EXPIRED':
          return 'EXPIRED';
        case 'VERIFY_INVALID':
          return 'INVALID';
        case 'DEACTIVATE_START':
          return 'DEACTIVATING';
        case 'RESET_TO_UNLICENSED':
          return 'UNLICENSED';
        default:
          return currentState;
      }
    }

    case 'GRACE_PERIOD': {
      switch (event.type) {
        case 'VERIFY_START':
          return 'VERIFYING';
        case 'VERIFY_SUCCESS':
          return 'ACTIVE';
        case 'GRACE_EXPIRED':
        case 'RESET_TO_UNLICENSED':
          return 'UNLICENSED';
        case 'VERIFY_EXPIRED':
          return 'EXPIRED';
        case 'VERIFY_INVALID':
          return 'INVALID';
        case 'DEACTIVATE_START':
          return 'DEACTIVATING';
        default:
          return currentState;
      }
    }

    case 'DEACTIVATING': {
      switch (event.type) {
        case 'DEACTIVATE_SUCCESS':
        case 'RESET_TO_UNLICENSED':
          return 'UNLICENSED';
        case 'DEACTIVATE_FAIL':
          return 'ACTIVE';
        default:
          return currentState;
      }
    }

    default:
      return currentState;
  }
}

/**
 * Checks whether the current state represents an active / valid entitlement
 */
export function isLicenseEntitled(state: LicenseState): boolean {
  return state === 'ACTIVE' || state === 'GRACE_PERIOD';
}

/**
 * Determines whether the license input field must be rendered in the DOM.
 * STRICT CRITERIA: Rendered ONLY when state is UNLICENSED, INVALID, EXPIRED,
 * or ERROR with no stored valid key. Never rendered if a valid license exists.
 */
export function shouldRenderActivationInput(
  state: LicenseState,
  hasStoredValidLicense: boolean
): boolean {
  if (hasStoredValidLicense) {
    return false;
  }
  return (
    state === 'UNLICENSED' ||
    state === 'INVALID' ||
    state === 'EXPIRED' ||
    state === 'ERROR'
  );
}

/**
 * Calculates offline grace period days remaining
 */
export function calculateGracePeriod(
  lastVerifiedEpoch: number,
  nowEpoch: number = Date.now()
): { isWithinGrace: boolean; daysRemaining: number; elapsedMs: number } {
  const elapsed = Math.max(0, nowEpoch - lastVerifiedEpoch);
  const remainingMs = Math.max(0, GRACE_PERIOD_MS - elapsed);
  const daysRemaining = Math.ceil(remainingMs / (24 * 60 * 60 * 1000));
  return {
    isWithinGrace: elapsed <= GRACE_PERIOD_MS,
    daysRemaining,
    elapsedMs: elapsed,
  };
}

/**
 * Calculates subscription days left until expiration
 */
export function calculateDaysLeft(
  expiresAtIso: string | null,
  nowEpoch: number = Date.now()
): { isExpired: boolean; daysLeft: number; label: string } {
  if (!expiresAtIso) {
    return { isExpired: false, daysLeft: Infinity, label: 'Lifetime entitlement' };
  }
  const expTime = new Date(expiresAtIso).getTime();
  if (isNaN(expTime)) {
    return { isExpired: false, daysLeft: 0, label: 'Unknown' };
  }
  const diff = expTime - nowEpoch;
  if (diff <= 0) {
    return { isExpired: true, daysLeft: 0, label: 'Expired' };
  }
  const daysLeft = Math.ceil(diff / (24 * 60 * 60 * 1000));
  return {
    isExpired: false,
    daysLeft,
    label: `${daysLeft} day${daysLeft === 1 ? '' : 's'} left`,
  };
}

/**
 * Badge configurations for each state
 * Every badge combines color, icon, and text (never color alone)
 */
export const STATE_BADGE_CONFIGS: Record<LicenseState, StateBadgeConfig> = {
  UNLICENSED: {
    label: 'Freemium Plan',
    variant: 'neutral',
    icon: 'shield',
    ariaLabel: 'Freemium tier active',
  },
  ACTIVE: {
    label: 'Active License',
    variant: 'success',
    icon: 'check-circle',
    ariaLabel: 'Active verified license',
  },
  GRACE_PERIOD: {
    label: 'Grace Period',
    variant: 'warning',
    icon: 'alert-triangle',
    ariaLabel: 'Offline grace period: server currently unreachable',
  },
  EXPIRED: {
    label: 'Expired',
    variant: 'warning',
    icon: 'clock',
    ariaLabel: 'License has expired',
    hasRenewLink: true,
  },
  INVALID: {
    label: 'Invalid / Revoked',
    variant: 'danger',
    icon: 'x-circle',
    ariaLabel: 'License key is invalid or revoked',
  },
  ERROR: {
    label: 'Connection Error',
    variant: 'danger',
    icon: 'wifi-off',
    ariaLabel: 'Network error communicating with license verification server',
  },
  VERIFYING: {
    label: 'Verifying...',
    variant: 'info',
    icon: 'spinner',
    ariaLabel: 'Verifying license with cloud server',
  },
  DEACTIVATING: {
    label: 'Deactivating...',
    variant: 'info',
    icon: 'spinner',
    ariaLabel: 'Deactivating license for this device',
  },
};
