/**
 * KotSafe Settings Activation Section Component
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Requirements:
 * 1. Single source of truth state machine
 * 2. Status card (always visible)
 * 3. Activation form (RENDERED ONLY when state is UNLICENSED, INVALID, EXPIRED,
 *    or ERROR with no stored valid key). NEVER rendered in the DOM when a valid license exists.
 * 4. Licensed view actions (ACTIVE / GRACE_PERIOD)
 * 5. Toast notifications and field errors
 */

import React, { useState, useCallback } from 'react';
import { useLicense } from '../hooks/useLicense.ts';
import { StatusCard } from './StatusCard.tsx';
import { ActivationForm } from './ActivationForm.tsx';
import { LicensedActions } from './LicensedActions.tsx';
import { FeatureComparison } from './FeatureComparison.tsx';
import { ToastContainer } from './ToastContainer.tsx';
import { ToastMessage } from '../types/license.ts';
import { Translations } from '../i18n/translations.ts';

interface ActivationSectionProps {
  t: Translations;
  onUpgradeClick?: () => void;
}

export const ActivationSection: React.FC<ActivationSectionProps> = ({
  t,
  onUpgradeClick,
}) => {
  const {
    state,
    record,
    isLicensed,
    planName,
    maskedKey,
    daysLeftLabel,
    graceDaysLeft,
    cooldownSeconds,
    shouldRenderInput,
    activate,
    revalidate,
    deactivate,
  } = useLicense();

  const [toasts, setToasts] = useState<ToastMessage[]>([]);
  const [showFeatureMatrix, setShowFeatureMatrix] = useState(false);

  const addToast = useCallback(
    (type: ToastMessage['type'], message: string, title?: string) => {
      const id = `${Date.now()}-${Math.random().toString(36).substring(2, 7)}`;
      const newToast: ToastMessage = { id, type, message, title };
      setToasts(prev => [...prev, newToast]);

      setTimeout(() => {
        setToasts(prev => prev.filter(t => t.id !== id));
      }, 5000);
    },
    []
  );

  const dismissToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id));
  }, []);

  const isVerifying = state === 'VERIFYING';

  return (
    <section
      className="activation-section"
      aria-labelledby="activation-section-heading"
      data-testid="activation-section"
    >
      <div className="section-header-row">
        <div>
          <h2 id="activation-section-heading" className="section-title">
            <svg
              className="section-title-icon"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2.2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
              <path d="M7 11V7a5 5 0 0 1 10 0v4" />
            </svg>
            {t.activationTitle}
          </h2>
          <p className="section-description">{t.activationSubtitle}</p>
        </div>

        <button
          type="button"
          className="btn-toggle-matrix"
          onClick={() => setShowFeatureMatrix(!showFeatureMatrix)}
          aria-expanded={showFeatureMatrix}
          data-testid="toggle-feature-matrix"
        >
          {showFeatureMatrix ? 'Hide Tier Matrix' : 'View Feature Matrix'}
        </button>
      </div>

      {/* A. Status Card - ALWAYS VISIBLE */}
      <StatusCard
        state={state}
        record={record}
        maskedKey={maskedKey}
        planName={planName}
        daysLeftLabel={daysLeftLabel}
        graceDaysLeft={graceDaysLeft}
        t={t}
        onUpgradeClick={onUpgradeClick}
        onRenewClick={() => {
          window.open('https://kotsafe.io/renew', '_blank', 'noopener,noreferrer');
        }}
      />

      {/* Optional Feature Matrix Modal/Accordion */}
      {showFeatureMatrix && <FeatureComparison t={t} />}

      {/*
        B. Activation Form - RENDERED ONLY when state is UNLICENSED, INVALID,
        EXPIRED, or ERROR with no stored valid key.
        CRITICAL: MUST NOT EXIST IN THE DOM AT ALL WHEN A VALID LICENSE EXISTS.
      */}
      {shouldRenderInput && (
        <ActivationForm
          isVerifying={isVerifying}
          cooldownSeconds={cooldownSeconds}
          t={t}
          onActivate={activate}
          onSuccessToast={msg => addToast('success', msg, 'License Activated')}
        />
      )}

      {/*
        C. Licensed View Actions - Shown ONLY when state is ACTIVE or GRACE_PERIOD.
        No input field rendered here.
      */}
      {isLicensed && (
        <LicensedActions
          isVerifying={isVerifying}
          t={t}
          onRevalidate={revalidate}
          onDeactivate={deactivate}
          onSuccessToast={msg => addToast('success', msg)}
          onErrorToast={msg => addToast('error', msg, 'Verification Error')}
        />
      )}

      {/* D. Accessible Toast Notifications */}
      <ToastContainer toasts={toasts} onDismiss={dismissToast} />
    </section>
  );
};
