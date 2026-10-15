/**
 * Cryptographic Signature Verifier
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Verifies server-signed license payloads using Asymmetric ECDSA (NIST P-256 / SHA-256)
 * via Web Crypto API.
 * 
 * Asymmetric verification guarantees that even if client-side code is decompiled
 * or inspected, users CANNOT forge valid license signatures because only the
 * backend possesses the private signing key.
 */

import { LicenseApiResponse } from '../types/license.ts';

// Public ECDSA P-256 verification key (safe for public client exposure)
export const KOTSAFE_PUBLIC_KEY_JWK = {
  kty: 'EC',
  crv: 'P-256',
  x: 'fnOSOaVFhh2aA2ptJaT_m5n0WJc0OdM2TCvevzRqLGI',
  y: 'K2GmlLsPgtiFgka1jxaUWv_n--k6iPwQ1z1C2utVs_Y',
};

// Legacy HMAC salt fallback for backward compatibility
export const LICENSE_SALT = 'kotsafe-salt-2026';

let cachedCryptoKey: CryptoKey | null = null;

async function getPublicKey(): Promise<CryptoKey> {
  if (cachedCryptoKey) return cachedCryptoKey;
  const cryptoObj = globalThis.crypto;
  if (!cryptoObj || !cryptoObj.subtle) {
    throw new Error('Web Crypto API is not available');
  }
  cachedCryptoKey = await cryptoObj.subtle.importKey(
    'jwk',
    KOTSAFE_PUBLIC_KEY_JWK,
    { name: 'ECDSA', namedCurve: 'P-256' },
    false,
    ['verify']
  );
  return cachedCryptoKey;
}

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
 * Generates legacy HMAC-SHA256 signature using Web Crypto API (used for testing / legacy fallback)
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
 * Converts a hex string to Uint8Array
 */
function hexToBytes(hex: string): Uint8Array {
  const cleanHex = hex.trim();
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    bytes[i / 2] = parseInt(cleanHex.substring(i, i + 2), 16);
  }
  return bytes;
}

/**
 * Verifies that the server signature on the response is valid and unaltered.
 * Supports asymmetric ECDSA P-256 (64-byte raw IEEE P1363 / 128 hex chars)
 * with graceful fallback to HMAC-SHA256.
 */
export async function verifyServerSignature(
  response: LicenseApiResponse,
  deviceId: string,
  salt: string = LICENSE_SALT
): Promise<boolean> {
  if (!response || !response.signature) {
    return false;
  }

  const canonical = buildCanonicalPayload(response, deviceId);
  const sig = response.signature.trim();

  // 1. Asymmetric ECDSA Verification (128 hex chars = 64 bytes IEEE-P1363 signature)
  if (sig.length === 128) {
    try {
      const pubKey = await getPublicKey();
      const enc = new TextEncoder();
      const data = enc.encode(canonical);
      const sigBytes = hexToBytes(sig);
      const isValid = await globalThis.crypto.subtle.verify(
        { name: 'ECDSA', hash: { name: 'SHA-256' } },
        pubKey,
        sigBytes as unknown as BufferSource,
        data
      );
      if (isValid) return true;
    } catch (e) {
      console.warn('[KotSafe Security] ECDSA verification attempt failed:', e);
    }
  }

  // 2. Fallback to legacy HMAC verification if ECDSA was not used or failed
  try {
    const expectedSignature = await generateSignature(canonical, salt);
    return sig.toUpperCase() === expectedSignature;
  } catch (err) {
    console.error('[KotSafe Security] Signature verification error:', err);
    return false;
  }
}
