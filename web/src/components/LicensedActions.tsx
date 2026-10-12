/**
 * KotSafe Licensed Actions Component
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Requirements:
 * - Rendered when license state is ACTIVE or GRACE_PERIOD.
 * - Actions: "Re-validate now", "Deactivate this device", "Manage license" (external link).
 */

import React, { useRef, useState } from 'react';
import { DeactivateModal } from './DeactivateModal.tsx';
import { Translations } from '../i18n/translations.ts';

interface LicensedActionsProps {
  isVerifying: boolean;
  t: Translations;
  onRevalidate: () => Promise<{ success: boolean; error?: string }>;
  onDeactivate: () => Promise<{ success: boolean; error?: string }>;
  onSuccessToast: (msg: string) => void;
  onErrorToast: (msg: string) => void;
  managePortalUrl?: string;
}

export const LicensedActions: React.FC<LicensedActionsProps> = ({
  isVerifying,
  t,
  onRevalidate,
  onDeactivate,
  onSuccessToast,
  onErrorToast,
  managePortalUrl = 'https://kotsafe.io/account/licenses',
}) => {
  const [isModalOpen, setIsModalOpen] = useState(false);
  const [isDeactivating, setIsDeactivating] = useState(false);
  const deactivateBtnRef = useRef<HTMLButtonElement>(null);

  const handleRevalidate = async () => {
    try {
      const res = await onRevalidate();
      if (res.success) {
        onSuccessToast(t.revalidationSuccessToast);
      } else if (res.error) {
        onErrorToast(res.error);
      }
    } catch (err) {
      onErrorToast(err instanceof Error ? err.message : 'Re-validation error');
    }
  };

  const handleConfirmDeactivate = async () => {
    setIsDeactivating(true);
    try {
      const res = await onDeactivate();
      setIsDeactivating(false);
      setIsModalOpen(false);

      if (res.success) {
        onSuccessToast(t.deactivationSuccessToast);
      } else if (res.error) {
        onErrorToast(res.error);
      }
    } catch (err) {
      setIsDeactivating(false);
      setIsModalOpen(false);
      onErrorToast(err instanceof Error ? err.message : 'Deactivation failed');
    }
  };

  return (
    <div className="licensed-actions-panel" data-testid="licensed-actions">
      <div className="licensed-actions-group">
        {/* Re-validate Now */}
        <button
          type="button"
          className="btn btn-secondary"
          onClick={handleRevalidate}
          disabled={isVerifying}
          aria-busy={isVerifying}
          data-testid="revalidate-button"
        >
          {isVerifying ? (
            <>
              <span className="spinner-icon animate-spin" aria-hidden="true" />
              <span>{t.revalidatingBtn}</span>
            </>
          ) : (
            <>
              <svg
                width="16"
                height="16"
                viewBox="0 0 24 24"
                fill="none"
                stroke="currentColor"
                strokeWidth="2"
                strokeLinecap="round"
                strokeLinejoin="round"
                aria-hidden="true"
              >
                <path d="M21.5 2v6h-6M21.34 15.57a10 10 0 1 1-.57-8.38l5.67-5.67" />
              </svg>
              <span>{t.revalidateBtn}</span>
            </>
          )}
        </button>

        {/* Deactivate Device */}
        <button
          ref={deactivateBtnRef}
          type="button"
          className="btn btn-outline-danger"
          onClick={() => setIsModalOpen(true)}
          data-testid="deactivate-button"
        >
          <svg
            width="16"
            height="16"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M18.36 6.64a9 9 0 1 1-12.73 0" />
            <line x1="12" y1="2" x2="12" y2="12" />
          </svg>
          <span>{t.deactivateBtn}</span>
        </button>

        {/* Manage License (External Portal) */}
        <a
          href={managePortalUrl}
          target="_blank"
          rel="noopener noreferrer"
          className="btn btn-ghost"
          data-testid="manage-license-link"
          aria-label="Manage license on external customer portal"
        >
          <span>{t.manageLicenseLink}</span>
          <svg
            width="14"
            height="14"
            viewBox="0 0 24 24"
            fill="none"
            stroke="currentColor"
            strokeWidth="2"
            strokeLinecap="round"
            strokeLinejoin="round"
            aria-hidden="true"
          >
            <path d="M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6" />
            <polyline points="15 3 21 3 21 9" />
            <line x1="10" y1="14" x2="21" y2="3" />
          </svg>
        </a>
      </div>

      {/* Confirmation Modal */}
      <DeactivateModal
        isOpen={isModalOpen}
        isDeactivating={isDeactivating}
        t={t}
        onConfirm={handleConfirmDeactivate}
        onClose={() => setIsModalOpen(false)}
        triggerRef={deactivateBtnRef}
      />
    </div>
  );
};
