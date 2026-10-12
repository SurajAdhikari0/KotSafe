/**
 * KotSafe License Activation Form Component
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Requirements:
 * - RENDERED ONLY when state is UNLICENSED, INVALID, EXPIRED, or ERROR with no stored valid key.
 * - MUST NOT exist in the DOM when a valid license exists.
 * - Auto-uppercase, trims whitespace, accepts paste with dashes/spaces.
 * - Client-side regex format validation before calling API.
 * - Disable button while empty, malformed, or verifying; prevents double submits.
 * - Inline field error with aria-describedby and role="alert".
 * - Visible rate limit cooldown.
 * - Show/Hide key toggle and Paste convenience.
 */

import React, { useState, useRef, useId } from 'react';
import { normalizeLicenseKey, validateKeyFormat } from '../core/keyValidator.ts';
import { Translations } from '../i18n/translations.ts';

interface ActivationFormProps {
  isVerifying: boolean;
  cooldownSeconds: number;
  t: Translations;
  onActivate: (key: string) => Promise<{ success: boolean; error?: string }>;
  onSuccessToast: (msg: string) => void;
}

export const ActivationForm: React.FC<ActivationFormProps> = ({
  isVerifying,
  cooldownSeconds,
  t,
  onActivate,
  onSuccessToast,
}) => {
  const [inputValue, setInputValue] = useState('');
  const [showKey, setShowKey] = useState(false);
  const [fieldError, setFieldError] = useState<string | null>(null);
  const [pasteNotice, setPasteNotice] = useState<string | null>(null);
  const [isSubmitting, setIsSubmitting] = useState(false);

  const inputId = useId();
  const errorId = useId();
  const helperId = useId();
  const inputRef = useRef<HTMLInputElement>(null);

  const isRateLimited = cooldownSeconds > 0;

  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const raw = e.target.value;
    const formatted = normalizeLicenseKey(raw);
    setInputValue(formatted);

    // Clear error on edit
    if (fieldError) {
      setFieldError(null);
    }
  };

  const handlePaste = async () => {
    try {
      let text = '';
      if (navigator.clipboard && navigator.clipboard.readText) {
        text = await navigator.clipboard.readText();
      } else {
        setPasteNotice(t.pasteError);
        setTimeout(() => setPasteNotice(null), 3000);
        return;
      }

      if (text) {
        const formatted = normalizeLicenseKey(text);
        setInputValue(formatted);
        setFieldError(null);
        setPasteNotice(t.pasteSuccess);
        setTimeout(() => setPasteNotice(null), 2500);
        inputRef.current?.focus();
      }
    } catch {
      setPasteNotice(t.pasteError);
      setTimeout(() => setPasteNotice(null), 3000);
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();

    if (isSubmitting || isVerifying || isRateLimited) {
      return;
    }

    // Client-side regex format check before touching the network
    const validation = validateKeyFormat(inputValue);
    if (!validation.isValid) {
      setFieldError(validation.error || 'Invalid key format.');
      inputRef.current?.focus();
      return;
    }

    setIsSubmitting(true);
    setFieldError(null);

    try {
      const result = await onActivate(validation.normalized);
      setIsSubmitting(false);

      if (result.success) {
        setInputValue('');
        onSuccessToast(t.activationSuccessToast);
      } else {
        setFieldError(result.error || 'Activation failed.');
        inputRef.current?.focus();
      }
    } catch (err) {
      setIsSubmitting(false);
      const msg = err instanceof Error ? err.message : 'Activation error';
      setFieldError(msg);
      inputRef.current?.focus();
    }
  };

  const isValidFormat = inputValue.length >= 16;
  const isButtonDisabled =
    !inputValue.trim() ||
    !isValidFormat ||
    isSubmitting ||
    isVerifying ||
    isRateLimited;

  return (
    <div
      className="activation-form-card"
      data-testid="activation-form"
      aria-labelledby="activation-form-title"
    >
      <div className="activation-form-header">
        <h3 id="activation-form-title" className="activation-form-title">
          {t.activationTitle}
        </h3>
        <p className="activation-form-subtitle">{t.activationSubtitle}</p>
      </div>

      <form onSubmit={handleSubmit} noValidate className="activation-form">
        <div className="form-field-group">
          <label htmlFor={inputId} className="field-label">
            {t.inputLabel}
          </label>

          <div className={`input-wrapper ${fieldError ? 'input-has-error' : ''}`}>
            <input
              ref={inputRef}
              id={inputId}
              name="licenseKey"
              type={showKey ? 'text' : 'password'}
              autoComplete="off"
              autoCorrect="off"
              autoCapitalize="characters"
              spellCheck="false"
              placeholder={t.inputPlaceholder}
              value={inputValue}
              onChange={handleInputChange}
              disabled={isSubmitting || isVerifying || isRateLimited}
              aria-describedby={`${helperId} ${fieldError ? errorId : ''}`}
              aria-invalid={fieldError ? 'true' : 'false'}
              aria-required="true"
              className="license-text-input font-mono"
              data-testid="license-input"
            />

            {/* Show/Hide Toggle */}
            <button
              type="button"
              className="btn-icon-inside"
              onClick={() => setShowKey(!showKey)}
              aria-label={showKey ? t.hideKey : t.showKey}
              title={showKey ? t.hideKey : t.showKey}
              data-testid="toggle-visibility"
            >
              {showKey ? (
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24" />
                  <line x1="1" y1="1" x2="23" y2="23" />
                </svg>
              ) : (
                <svg
                  viewBox="0 0 24 24"
                  fill="none"
                  stroke="currentColor"
                  strokeWidth="2"
                  strokeLinecap="round"
                  strokeLinejoin="round"
                  aria-hidden="true"
                >
                  <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
                  <circle cx="12" cy="12" r="3" />
                </svg>
              )}
            </button>

            {/* Paste Convenience Button */}
            <button
              type="button"
              className="btn-paste"
              onClick={handlePaste}
              disabled={isSubmitting || isVerifying || isRateLimited}
              aria-label={t.pasteBtn}
              data-testid="paste-button"
            >
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
                <path d="M16 4h2a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2V6a2 2 0 0 1 2-2h2" />
                <rect x="8" y="2" width="8" height="4" rx="1" ry="1" />
              </svg>
              <span>{t.pasteBtn}</span>
            </button>
          </div>

          {/* Paste Notification feedback */}
          {pasteNotice && (
            <p className="paste-notice-text" role="status" aria-live="polite">
              {pasteNotice}
            </p>
          )}

          {/* Helper text */}
          <p id={helperId} className="field-helper-text">
            {t.inputHelper}
          </p>

          {/* Inline Field Error with aria-describedby */}
          {fieldError && (
            <div
              id={errorId}
              className="field-error-message"
              role="alert"
              aria-live="assertive"
              data-testid="field-error"
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
                <circle cx="12" cy="12" r="10" />
                <line x1="12" y1="8" x2="12" y2="12" />
                <line x1="12" y1="16" x2="12.01" y2="16" />
              </svg>
              <span>{fieldError}</span>
            </div>
          )}

          {/* Rate Limit Cooldown Warning */}
          {isRateLimited && (
            <div
              className="cooldown-warning"
              role="alert"
              aria-live="polite"
              data-testid="cooldown-warning"
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
                <circle cx="12" cy="12" r="10" />
                <polyline points="12 6 12 12 16 14" />
              </svg>
              <span>
                {t.cooldownMessage.replace('{seconds}', String(cooldownSeconds))}
              </span>
            </div>
          )}
        </div>

        {/* Submit Button */}
        <div className="form-submit-row">
          <button
            type="submit"
            className="btn btn-primary btn-activate"
            disabled={isButtonDisabled}
            data-testid="activate-submit-button"
            aria-busy={isSubmitting || isVerifying}
          >
            {isSubmitting || isVerifying ? (
              <>
                <span className="spinner-icon animate-spin" aria-hidden="true" />
                <span>{t.activatingBtn}</span>
              </>
            ) : (
              <>
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
                  <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
                </svg>
                <span>{t.activateBtn}</span>
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
};
