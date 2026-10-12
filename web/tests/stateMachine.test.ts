import { describe, it, expect } from 'vitest';
import {
  transitionLicenseState,
  isLicenseEntitled,
  shouldRenderActivationInput,
  calculateGracePeriod,
  calculateDaysLeft,
  STATE_BADGE_CONFIGS,
} from '../src/core/licenseStateMachine.ts';
import { LicenseState } from '../src/types/license.ts';

describe('License State Machine', () => {
  it('transitions UNLICENSED -> VERIFYING -> ACTIVE on success', () => {
    let state = transitionLicenseState('UNLICENSED', { type: 'VERIFY_START' });
    expect(state).toBe('VERIFYING');

    state = transitionLicenseState(state, { type: 'VERIFY_SUCCESS' });
    expect(state).toBe('ACTIVE');
    expect(isLicenseEntitled(state)).toBe(true);
  });

  it('transitions UNLICENSED -> VERIFYING -> INVALID on invalid key', () => {
    let state = transitionLicenseState('UNLICENSED', { type: 'VERIFY_START' });
    state = transitionLicenseState(state, { type: 'VERIFY_INVALID' });
    expect(state).toBe('INVALID');
    expect(isLicenseEntitled(state)).toBe(false);
  });

  it('transitions UNLICENSED -> VERIFYING -> EXPIRED on expired key', () => {
    let state = transitionLicenseState('UNLICENSED', { type: 'VERIFY_START' });
    state = transitionLicenseState(state, { type: 'VERIFY_EXPIRED' });
    expect(state).toBe('EXPIRED');
    expect(isLicenseEntitled(state)).toBe(false);
  });

  it('transitions UNLICENSED -> VERIFYING -> ERROR on network/server error', () => {
    let state = transitionLicenseState('UNLICENSED', { type: 'VERIFY_START' });
    state = transitionLicenseState(state, { type: 'VERIFY_ERROR', isGraceEligible: false });
    expect(state).toBe('ERROR');
    expect(isLicenseEntitled(state)).toBe(false);
  });

  it('transitions ACTIVE -> GRACE_PERIOD when server is unreachable within 7 days', () => {
    const lastVerified = Date.now() - 2 * 24 * 60 * 60 * 1000; // 2 days ago
    const state = transitionLicenseState('ACTIVE', {
      type: 'SERVER_UNREACHABLE',
      lastVerifiedEpoch: lastVerified,
    });
    expect(state).toBe('GRACE_PERIOD');
    expect(isLicenseEntitled(state)).toBe(true);
  });

  it('transitions ACTIVE -> UNLICENSED when server is unreachable for more than 7 days', () => {
    const lastVerified = Date.now() - 8 * 24 * 60 * 60 * 1000; // 8 days ago (> 7 days)
    const state = transitionLicenseState('ACTIVE', {
      type: 'SERVER_UNREACHABLE',
      lastVerifiedEpoch: lastVerified,
    });
    expect(state).toBe('UNLICENSED');
    expect(isLicenseEntitled(state)).toBe(false);
  });

  it('transitions ACTIVE -> DEACTIVATING -> UNLICENSED', () => {
    let state = transitionLicenseState('ACTIVE', { type: 'DEACTIVATE_START' });
    expect(state).toBe('DEACTIVATING');

    state = transitionLicenseState(state, { type: 'DEACTIVATE_SUCCESS' });
    expect(state).toBe('UNLICENSED');
    expect(isLicenseEntitled(state)).toBe(false);
  });

  it('restores ACTIVE if deactivation fails', () => {
    let state = transitionLicenseState('ACTIVE', { type: 'DEACTIVATE_START' });
    state = transitionLicenseState(state, { type: 'DEACTIVATE_FAIL' });
    expect(state).toBe('ACTIVE');
  });

  it('recovers from GRACE_PERIOD to ACTIVE when validation succeeds', () => {
    let state = transitionLicenseState('GRACE_PERIOD', { type: 'VERIFY_START' });
    state = transitionLicenseState(state, { type: 'VERIFY_SUCCESS' });
    expect(state).toBe('ACTIVE');
  });

  describe('shouldRenderActivationInput (Strict DOM Presence Rule)', () => {
    it('returns false whenever a valid license is stored', () => {
      const allStates: LicenseState[] = [
        'UNLICENSED',
        'VERIFYING',
        'ACTIVE',
        'INVALID',
        'EXPIRED',
        'ERROR',
        'GRACE_PERIOD',
        'DEACTIVATING',
      ];
      allStates.forEach(state => {
        expect(shouldRenderActivationInput(state, true)).toBe(false);
      });
    });

    it('returns true when state is UNLICENSED, INVALID, EXPIRED, or ERROR and no valid key stored', () => {
      expect(shouldRenderActivationInput('UNLICENSED', false)).toBe(true);
      expect(shouldRenderActivationInput('INVALID', false)).toBe(true);
      expect(shouldRenderActivationInput('EXPIRED', false)).toBe(true);
      expect(shouldRenderActivationInput('ERROR', false)).toBe(true);
    });

    it('returns false during VERIFYING, ACTIVE, GRACE_PERIOD, or DEACTIVATING', () => {
      expect(shouldRenderActivationInput('VERIFYING', false)).toBe(false);
      expect(shouldRenderActivationInput('ACTIVE', false)).toBe(false);
      expect(shouldRenderActivationInput('GRACE_PERIOD', false)).toBe(false);
      expect(shouldRenderActivationInput('DEACTIVATING', false)).toBe(false);
    });
  });

  describe('Grace Period and Expiry Calculations', () => {
    it('calculates remaining days within 7 days', () => {
      const now = Date.now();
      const threeDaysAgo = now - 3 * 24 * 60 * 60 * 1000;
      const grace = calculateGracePeriod(threeDaysAgo, now);

      expect(grace.isWithinGrace).toBe(true);
      expect(grace.daysRemaining).toBe(4);
    });

    it('detects grace period expiration after 7 days', () => {
      const now = Date.now();
      const eightDaysAgo = now - 8 * 24 * 60 * 60 * 1000;
      const grace = calculateGracePeriod(eightDaysAgo, now);

      expect(grace.isWithinGrace).toBe(false);
      expect(grace.daysRemaining).toBe(0);
    });

    it('calculates expiration countdown correctly', () => {
      const future = new Date(Date.now() + 10 * 24 * 60 * 60 * 1000).toISOString();
      const days = calculateDaysLeft(future);
      expect(days.isExpired).toBe(false);
      expect(days.daysLeft).toBe(10);
      expect(days.label).toContain('10 days left');
    });

    it('detects already expired license', () => {
      const past = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
      const days = calculateDaysLeft(past);
      expect(days.isExpired).toBe(true);
      expect(days.label).toBe('Expired');
    });
  });

  describe('Badge Configurations (Color + Icon + Text, never color alone)', () => {
    const states: LicenseState[] = [
      'UNLICENSED',
      'ACTIVE',
      'GRACE_PERIOD',
      'EXPIRED',
      'INVALID',
      'ERROR',
      'VERIFYING',
      'DEACTIVATING',
    ];

    states.forEach(state => {
      it(`config for ${state} includes label, semantic variant, accessible icon and ariaLabel`, () => {
        const config = STATE_BADGE_CONFIGS[state];
        expect(config).toBeDefined();
        expect(config.label.length).toBeGreaterThan(0);
        expect(config.icon.length).toBeGreaterThan(0);
        expect(config.variant.length).toBeGreaterThan(0);
        expect(config.ariaLabel.length).toBeGreaterThan(0);
      });
    });

    it('EXPIRED state badge includes hasRenewLink flag', () => {
      expect(STATE_BADGE_CONFIGS.EXPIRED.hasRenewLink).toBe(true);
    });
  });
});
