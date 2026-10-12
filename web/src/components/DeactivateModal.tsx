/**
 * KotSafe License Deactivation Confirmation Modal
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Requirements:
 * - WCAG 2.1 AA accessible modal dialog
 * - Focus trapped inside modal while open
 * - Focus returned to trigger element upon closing
 * - Closes on Escape key
 * - Explains seat will be freed on server
 */

import React, { useEffect, useRef } from 'react';
import { Translations } from '../i18n/translations.ts';

interface DeactivateModalProps {
  isOpen: boolean;
  isDeactivating: boolean;
  t: Translations;
  onConfirm: () => void;
  onClose: () => void;
  triggerRef?: React.RefObject<HTMLButtonElement | null>;
}

export const DeactivateModal: React.FC<DeactivateModalProps> = ({
  isOpen,
  isDeactivating,
  t,
  onConfirm,
  onClose,
  triggerRef,
}) => {
  const modalRef = useRef<HTMLDivElement>(null);
  const confirmBtnRef = useRef<HTMLButtonElement>(null);

  // Return focus on close and handle Escape
  useEffect(() => {
    if (!isOpen) return;

    // Focus initial confirm button
    const timer = setTimeout(() => {
      confirmBtnRef.current?.focus();
    }, 50);

    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault();
        onClose();
        return;
      }

      // Trap focus
      if (e.key === 'Tab' && modalRef.current) {
        const focusable = modalRef.current.querySelectorAll<HTMLElement>(
          'button, [href], input, select, textarea, [tabindex]:not([tabindex="-1"])'
        );
        if (focusable.length === 0) return;

        const first = focusable[0];
        const last = focusable[focusable.length - 1];

        if (e.shiftKey && document.activeElement === first) {
          e.preventDefault();
          last.focus();
        } else if (!e.shiftKey && document.activeElement === last) {
          e.preventDefault();
          first.focus();
        }
      }
    };

    document.addEventListener('keydown', handleKeyDown);

    return () => {
      clearTimeout(timer);
      document.removeEventListener('keydown', handleKeyDown);
      // Restore focus to trigger element
      triggerRef?.current?.focus();
    };
  }, [isOpen, onClose, triggerRef]);

  if (!isOpen) return null;

  return (
    <div
      className="modal-backdrop"
      onClick={e => {
        if (e.target === e.currentTarget && !isDeactivating) {
          onClose();
        }
      }}
      role="presentation"
    >
      <div
        ref={modalRef}
        className="modal-dialog"
        role="dialog"
        aria-modal="true"
        aria-labelledby="deactivate-modal-title"
        aria-describedby="deactivate-modal-desc"
        data-testid="deactivate-modal"
      >
        <div className="modal-header">
          <div className="modal-icon-danger">
            <svg
              width="24"
              height="24"
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
          </div>
          <div>
            <h3 id="deactivate-modal-title" className="modal-title">
              {t.deactivateModalTitle}
            </h3>
          </div>
        </div>

        <div className="modal-body">
          <p id="deactivate-modal-desc" className="modal-text">
            {t.deactivateModalBody}
          </p>
          <div className="seat-release-notice">
            <svg
              width="18"
              height="18"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="2"
              strokeLinecap="round"
              strokeLinejoin="round"
              aria-hidden="true"
            >
              <polyline points="20 6 9 17 4 12" />
            </svg>
            <span>
              1 device slot will be immediately freed and returned to your subscription pool.
            </span>
          </div>
        </div>

        <div className="modal-footer">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={onClose}
            disabled={isDeactivating}
            data-testid="modal-cancel-btn"
          >
            {t.deactivateModalCancel}
          </button>
          <button
            ref={confirmBtnRef}
            type="button"
            className="btn btn-danger"
            onClick={onConfirm}
            disabled={isDeactivating}
            data-testid="modal-confirm-btn"
            aria-busy={isDeactivating}
          >
            {isDeactivating ? (
              <>
                <span className="spinner-icon animate-spin" aria-hidden="true" />
                <span>Deactivating...</span>
              </>
            ) : (
              t.deactivateModalConfirm
            )}
          </button>
        </div>
      </div>
    </div>
  );
};
