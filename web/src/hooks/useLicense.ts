/**
 * KotSafe Global useLicense Hook
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Exposes license state machine, reactive updates, feature gating,
 * and activation/deactivation actions for any component in the application.
 */

import { useState, useEffect, useCallback, useMemo } from 'react';
import {
  FeatureKey,
  LicensePlan,
  LicenseRecord,
  LicenseState,
} from '../types/license.ts';
import { licenseService } from '../services/licenseService.ts';
import {
  calculateDaysLeft,
  calculateGracePeriod,
  isLicenseEntitled,
  shouldRenderActivationInput,
} from '../core/licenseStateMachine.ts';
import { checkRateLimit } from '../security/secureStorage.ts';
import { maskKey } from '../core/keyValidator.ts';

export interface UseLicenseReturn {
  state: LicenseState;
  record: LicenseRecord | null;
  isLicensed: boolean;
  isPro: boolean;
  isEnterprise: boolean;
  isGracePeriod: boolean;
  plan: LicensePlan;
  planName: string;
  maskedKey: string;
  daysLeft: number;
  daysLeftLabel: string;
  graceDaysLeft: number;
  cooldownSeconds: number;
  shouldRenderInput: boolean;
  activate: (key: string) => Promise<{ success: boolean; error?: string }>;
  revalidate: () => Promise<{ success: boolean; error?: string }>;
  deactivate: () => Promise<{ success: boolean; error?: string }>;
  canAccessFeature: (feature: FeatureKey) => boolean;
}

export function useLicense(): UseLicenseReturn {
  // Synchronous initial state from service (no flash)
  const [state, setState] = useState<LicenseState>(licenseService.getState());
  const [record, setRecord] = useState<LicenseRecord | null>(licenseService.getRecord());
  const [cooldownSeconds, setCooldownSeconds] = useState<number>(() => {
    return checkRateLimit().cooldownRemainingSeconds;
  });

  // Subscribe to service state changes
  useEffect(() => {
    const unsubscribe = licenseService.subscribe((newState, newRecord) => {
      setState(newState);
      setRecord(newRecord);
    });

    // Check rate limit timer
    const rateTimer = setInterval(() => {
      const { cooldownRemainingSeconds } = checkRateLimit();
      setCooldownSeconds(cooldownRemainingSeconds);
    }, 1000);

    return () => {
      unsubscribe();
      clearInterval(rateTimer);
    };
  }, []);

  const isLicensed = isLicenseEntitled(state);
  const isGracePeriod = state === 'GRACE_PERIOD';
  const plan: LicensePlan = record?.plan || 'freemium';

  const planName = useMemo(() => {
    switch (plan) {
      case 'enterprise':
        return 'KotSafe Enterprise Suite';
      case 'pro':
        return 'KotSafe Pro Security';
      default:
        return 'KotSafe Community (Freemium)';
    }
  }, [plan]);

  const maskedKey = useMemo(() => {
    return maskKey(record?.key);
  }, [record?.key]);

  const { daysLeft, label: daysLeftLabel } = useMemo(() => {
    return calculateDaysLeft(record?.expiresAt ?? null);
  }, [record?.expiresAt]);

  const graceDaysLeft = useMemo(() => {
    if (!record?.lastVerifiedAt) return 0;
    const epoch = new Date(record.lastVerifiedAt).getTime();
    return calculateGracePeriod(epoch).daysRemaining;
  }, [record?.lastVerifiedAt]);

  const shouldRenderInput = useMemo(() => {
    return shouldRenderActivationInput(state, !!record);
  }, [state, record]);

  const activate = useCallback(async (key: string) => {
    return licenseService.activate(key);
  }, []);

  const revalidate = useCallback(async () => {
    return licenseService.revalidate();
  }, []);

  const deactivate = useCallback(async () => {
    return licenseService.deactivate();
  }, []);

  const canAccessFeature = useCallback((feature: FeatureKey) => {
    return licenseService.canAccessFeature(feature);
  }, []);

  return {
    state,
    record,
    isLicensed,
    isPro: plan === 'pro',
    isEnterprise: plan === 'enterprise',
    isGracePeriod,
    plan,
    planName,
    maskedKey,
    daysLeft,
    daysLeftLabel,
    graceDaysLeft,
    cooldownSeconds,
    shouldRenderInput,
    activate,
    revalidate,
    deactivate,
    canAccessFeature,
  };
}
