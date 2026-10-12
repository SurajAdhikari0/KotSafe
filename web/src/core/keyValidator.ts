/**
 * KotSafe License Key Validator & Masker
 * Copyright (c) 2026 KotSafe Cyber Security Project
 */

// Format: KOT-(PRO|ENT|DEV)-[4-10 alphanumeric chars]-[4-8 checksum chars]
export const KEY_FORMAT_REGEX = /^KOT-(PRO|ENT|DEV)-[A-Z0-9]{4,10}-[A-Z0-9]{4,8}$/;

/**
 * Normalizes input:
 * - Trims leading and trailing whitespace
 * - Converts to uppercase
 * - Strips unwanted special characters (XSS/injection safe)
 * - Converts spaces or multiple consecutive hyphens into single hyphens
 */
export function normalizeLicenseKey(rawKey: string): string {
  if (!rawKey) return '';
  return rawKey
    .trim()
    .toUpperCase()
    // Replace spaces, underscores or multiple dashes with a single dash
    .replace(/[\s_]+/g, '-')
    // Remove any character that is not alphanumeric or hyphen
    .replace(/[^A-Z0-9-]/g, '')
    // Consolidate repeating dashes
    .replace(/-+/g, '-');
}

/**
 * Validates whether a key satisfies client-side format requirements
 */
export function validateKeyFormat(key: string): {
  isValid: boolean;
  error?: string;
  normalized: string;
} {
  const normalized = normalizeLicenseKey(key);

  if (!normalized) {
    return {
      isValid: false,
      error: 'License key cannot be empty.',
      normalized: '',
    };
  }

  if (!normalized.startsWith('KOT-')) {
    return {
      isValid: false,
      error: 'Invalid key prefix. KotSafe keys must begin with "KOT-".',
      normalized,
    };
  }

  const parts = normalized.split('-');
  if (parts.length < 4) {
    return {
      isValid: false,
      error: 'Key is incomplete. Expected format: KOT-PRO-XXXXXXXX-XXXX',
      normalized,
    };
  }

  const tier = parts[1];
  if (!['PRO', 'ENT', 'DEV'].includes(tier)) {
    return {
      isValid: false,
      error: `Unknown plan tier "${tier}". Expected PRO or ENT.`,
      normalized,
    };
  }

  if (!KEY_FORMAT_REGEX.test(normalized)) {
    return {
      isValid: false,
      error: 'Invalid key format. Please check the code and try again.',
      normalized,
    };
  }

  return {
    isValid: true,
    normalized,
  };
}

/**
 * Masks a license key for UI presentation, logs, and error reporting.
 * Exposes ONLY the last 4 characters, e.g. ****-****-****-A1B2.
 * NEVER leaks the full key.
 */
export function maskKey(key: string | null | undefined): string {
  if (!key) return 'None';
  const clean = normalizeLicenseKey(key);
  if (clean.length < 4) return '****';

  const last4 = clean.slice(-4);
  return `****-****-****-${last4}`;
}
