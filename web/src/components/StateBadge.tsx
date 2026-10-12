/**
 * KotSafe License State Badge Component
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Requirements:
 * - Color + Icon + Text (NEVER color alone)
 * - Freemium: neutral
 * - Active: success
 * - Grace period: warning
 * - Expired: warning with "Renew" link
 * - Invalid / Revoked: danger
 * - Verifying: spinner
 */

import React from 'react';
import { LicenseState } from '../types/license.ts';
import { STATE_BADGE_CONFIGS } from '../core/licenseStateMachine.ts';

interface StateBadgeProps {
  state: LicenseState;
  onRenewClick?: () => void;
  renewUrl?: string;
}

export const StateBadge: React.FC<StateBadgeProps> = ({
  state,
  onRenewClick,
  renewUrl = 'https://kotsafe.io/renew',
}) => {
  const config = STATE_BADGE_CONFIGS[state] || STATE_BADGE_CONFIGS.UNLICENSED;

  const renderIcon = () => {
    switch (config.icon) {
      case 'check-circle':
        return (
          <svg
            className="badge-icon icon-success"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M22 11.08V12a10 10 0 1 1-5.93-9.14" />
            <polyline points="22 4 12 14.01 9 11.01" />
          </svg>
        );

      case 'alert-triangle':
        return (
          <svg
            className="badge-icon icon-warning"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
            <line x1="12" y1="9" x2="12" y2="13" />
            <line x1="12" y1="17" x2="12.01" y2="17" />
          </svg>
        );

      case 'clock':
        return (
          <svg
            className="badge-icon icon-warning"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <circle cx="12" cy="12" r="10" />
            <polyline points="12 6 12 12 16 14" />
          </svg>
        );

      case 'x-circle':
        return (
          <svg
            className="badge-icon icon-danger"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <circle cx="12" cy="12" r="10" />
            <line x1="15" y1="9" x2="9" y2="15" />
            <line x1="9" y1="9" x2="15" y2="15" />
          </svg>
        );

      case 'wifi-off':
        return (
          <svg
            className="badge-icon icon-danger"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <line x1="1" y1="1" x2="23" y2="23" />
            <path d="M16.72 11.06A10.94 10.94 0 0 1 19 12.55" />
            <path d="M5 12.55a10.94 10.94 0 0 1 5.17-2.39" />
            <path d="M10.71 5.05A16 16 0 0 1 22.58 9" />
            <path d="M1.42 9a15.91 15.91 0 0 1 4.7-2.88" />
            <path d="M8.53 16.11a6 6 0 0 1 6.95 0" />
            <line x1="12" y1="20" x2="12.01" y2="20" />
          </svg>
        );

      case 'spinner':
        return (
          <svg
            className="badge-icon icon-spinner animate-spin"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <line x1="12" y1="2" x2="12" y2="6" />
            <line x1="12" y1="18" x2="12" y2="22" />
            <line x1="4.93" y1="4.93" x2="7.76" y2="7.76" />
            <line x1="16.24" y1="16.24" x2="19.07" y2="19.07" />
            <line x1="2" y1="12" x2="6" y2="12" />
            <line x1="18" y1="12" x2="22" y2="12" />
            <line x1="4.93" y1="19.07" x2="7.76" y2="16.24" />
            <line x1="16.24" y1="7.76" x2="19.07" y2="4.93" />
          </svg>
        );

      case 'shield':
      default:
        return (
          <svg
            className="badge-icon icon-neutral"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2.5"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
        );
    }
  };

  return (
    <div
      className={`state-badge badge-${config.variant}`}
      role="status"
      aria-label={config.ariaLabel}
      data-testid="state-badge"
    >
      <span className="badge-icon-wrapper">{renderIcon()}</span>
      <span className="badge-text">{config.label}</span>
      {config.hasRenewLink && (
        <a
          href={renewUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="badge-renew-link"
          onClick={e => {
            if (onRenewClick) {
              e.preventDefault();
              onRenewClick();
            }
          }}
          aria-label="Renew expired license subscription"
        >
          Renew &rarr;
        </a>
      )}
    </div>
  );
};
