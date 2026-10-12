/**
 * Cryptographic Signature Verifier
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Verifies server-signed license payloads using HMAC-SHA256 via Web Crypto API.
 * Prevents tampered responses (e.g. modified plan or expiry) from unlocking features.
 */

import { LicenseApiResponse } from '../types/license.ts';

// Shared verification salt matching KotSafe backend signaling service
export const LICENSE_SALT = 'kotsafe-salt-2026';

/**
 * Builds the canonical deterministic string for signature verification
 */
export function buildCanonicalPayload(
  response: Pick<LicenseApiResponse, 'status' | 'plan' | 'expiresAt' | 'seats'>,
  deviceId: string
): string {
  const expires = response.expiresAt || '';
  const used = response.seats?.used ?? 0;
  const max = response.seats?.max ?? 0;
  return `${response.status}:${response.plan}:${expires}:${used}:${max}:${deviceId}`;
}

/**
 * Generates HMAC-SHA256 signature using Web Crypto API
 */
export async function generateSignature(
  canonicalPayload: string,
  salt: string = LICENSE_SALT
): Promise<string> {
  const enc = new TextEncoder();
  const keyData = enc.encode(salt);
  const data = enc.encode(canonicalPayload);

  const cryptoObj = globalThis.crypto;
  if (!cryptoObj || !cryptoObj.subtle) {
    throw new Error('Web Crypto API is not available');
  }

  const cryptoKey = await cryptoObj.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );

  const signatureBuffer = await cryptoObj.subtle.sign('HMAC', cryptoKey, data);
  const hashArray = Array.from(new Uint8Array(signatureBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
}

/**
 * Verifies that the server signature on the response is valid and unaltered.
 */
export async function verifyServerSignature(
  response: LicenseApiResponse,
  deviceId: string,
  salt: string = LICENSE_SALT
): Promise<boolean> {
  if (!response || !response.signature) {
    return false;
  }

  try {
    const canonical = buildCanonicalPayload(response, deviceId);
    const expectedSignature = await generateSignature(canonical, salt);
    return response.signature.toUpperCase() === expectedSignature;
  } catch (err) {
    console.error('[KotSafe Security] Signature verification error:', err);
    return false;
  }
}
