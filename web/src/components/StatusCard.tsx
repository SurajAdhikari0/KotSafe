/**
 * KotSafe License Status Card Component
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Requirements:
 * - Always visible in the DOM
 * - Badge, plan/tier name, masked key, activation date, expiry date ("X days left"),
 *   seats used ("1 of 3"), last verified timestamp.
 * - Feature comparison hint for Freemium users with "Upgrade" / "Buy license" link.
 */

import React from 'react';
import { LicenseRecord, LicenseState } from '../types/license.ts';
import { StateBadge } from './StateBadge.tsx';
import { Translations } from '../i18n/translations.ts';

interface StatusCardProps {
  state: LicenseState;
  record: LicenseRecord | null;
  maskedKey: string;
  planName: string;
  daysLeftLabel: string;
  graceDaysLeft: number;
  t: Translations;
  onUpgradeClick?: () => void;
  onRenewClick?: () => void;
}

export const StatusCard: React.FC<StatusCardProps> = ({
  state,
  record,
  maskedKey,
  planName,
  daysLeftLabel,
  graceDaysLeft,
  t,
  onUpgradeClick,
  onRenewClick,
}) => {
  const isLicensed = state === 'ACTIVE' || state === 'GRACE_PERIOD';
  const isGrace = state === 'GRACE_PERIOD';

  const formatDate = (isoString?: string | null) => {
    if (!isoString) return '—';
    try {
      const d = new Date(isoString);
      return d.toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
      });
    } catch {
      return isoString;
    }
  };

  const formatTime = (isoString?: string | null) => {
    if (!isoString) return 'Never';
    try {
      const d = new Date(isoString);
      return `${d.toLocaleDateString(undefined, {
        month: 'short',
        day: 'numeric',
      })}, ${d.toLocaleTimeString(undefined, {
        hour: '2-digit',
        minute: '2-digit',
      })}`;
    } catch {
      return isoString;
    }
  };

  const seatsUsed = record?.seats?.used ?? (isLicensed ? 1 : 0);
  const seatsMax = record?.seats?.max ?? (isLicensed ? 6 : 1);

  return (
    <div
      className="status-card-container"
      data-testid="license-status-card"
      aria-labelledby="status-card-heading"
    >
      <div className="status-card-header">
        <div>
          <h3 id="status-card-heading" className="status-card-title">
            {t.statusCardTitle}
          </h3>
          <p className="status-plan-name" data-testid="plan-name">
            {planName}
          </p>
        </div>
        <StateBadge
          state={state}
          onRenewClick={onRenewClick}
          renewUrl="https://kotsafe.io/renew"
        />
      </div>

      {isGrace && (
        <div
          className="grace-period-banner"
          role="alert"
          aria-live="polite"
          data-testid="grace-period-banner"
        >
          <svg
            className="grace-icon"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
          <div>
            <strong>Offline Grace Period Active:</strong> The verification server
            is temporarily unreachable. Your full Pro cybersecurity features remain active
            offline for <strong>{graceDaysLeft} more days</strong>.
          </div>
        </div>
      )}

      {/* Grid of Entitlement Details */}
      <div className="status-metrics-grid">
        <div className="metric-item">
          <span className="metric-label">{t.licenseKeyLabel}</span>
          <span className="metric-value font-mono" data-testid="masked-key">
            {maskedKey}
          </span>
        </div>

        <div className="metric-item">
          <span className="metric-label">{t.seatsLabel}</span>
          <span className="metric-value" data-testid="seats-count">
            {seatsUsed} of {seatsMax} device{seatsMax === 1 ? '' : 's'}
          </span>
        </div>

        <div className="metric-item">
          <span className="metric-label">{t.activationDateLabel}</span>
          <span className="metric-value" data-testid="activation-date">
            {formatDate(record?.activatedAt)}
          </span>
        </div>

        <div className="metric-item">
          <span className="metric-label">{t.expiryDateLabel}</span>
          <span className="metric-value" data-testid="expiry-date">
            {record?.expiresAt ? (
              <>
                {formatDate(record.expiresAt)}{' '}
                <span className="expiry-days-pill">({daysLeftLabel})</span>
              </>
            ) : isLicensed ? (
              'Lifetime entitlement'
            ) : (
              '—'
            )}
          </span>
        </div>

        <div className="metric-item metric-full-row">
          <span className="metric-label">{t.lastVerifiedLabel}</span>
          <span className="metric-value font-mono text-muted" data-testid="last-verified">
            {formatTime(record?.lastVerifiedAt)}
          </span>
        </div>
      </div>

      {/* Feature comparison hint for Freemium or Expired users */}
      {!isLicensed && (
        <div className="freemium-hint-box" data-testid="freemium-hint-box">
          <div className="freemium-hint-content">
            <div className="freemium-hint-icon">
              <svg
                width="28"
                height="28"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z" />
              </svg>
            </div>
            <div>
              <h4 className="freemium-hint-title">{t.freemiumNoticeTitle}</h4>
              <p className="freemium-hint-desc">{t.freemiumNoticeDesc}</p>
            </div>
          </div>
          <div className="freemium-hint-actions">
            <button
              type="button"
              className="btn btn-upgrade"
              onClick={onUpgradeClick}
              data-testid="upgrade-button"
            >
              {t.upgradeBtn}
            </button>
            <a
              href="https://kotsafe.io/pricing"
              target="_blank"
              rel="noopener noreferrer"
              className="link-buy-license"
              aria-label="Buy KotSafe Pro license on official website"
            >
              <span dangerouslySetInnerHTML={{ __html: t.buyLicenseLink }} />
            </a>
          </div>
        </div>
      )}
    </div>
  );
};
