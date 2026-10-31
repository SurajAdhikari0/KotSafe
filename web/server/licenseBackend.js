/**
 * KotSafe License Backend API Server
 * Copyright (c) 2026 KotSafe Cyber Security Project
 *
 * Implements the official API contract:
 *   POST /license/activate    { key, deviceId, appVersion }
 *   POST /license/validate    { key, deviceId }
 *   POST /license/deactivate  { key, deviceId }
 *
 * Response contract:
 * {
 *   "status": "active|expired|invalid|revoked",
 *   "plan": "pro",
 *   "expiresAt": "ISO-8601 | null",
 *   "seats": { "used": 1, "max": 6 },
 *   "signature": "server-signed payload",
 *   "errorCode": "KEY_NOT_FOUND | SEAT_LIMIT | EXPIRED | RATE_LIMITED"
 * }
 */

import http from 'node:http';
import crypto from 'node:crypto';
import { applicationDefault, cert, getApps, initializeApp } from 'firebase-admin/app';
import { getAuth } from 'firebase-admin/auth';

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8080;
const SALT = process.env.LICENSE_SALT || (process.env.NODE_ENV === 'production'
  ? (() => { throw new Error('FATAL: LICENSE_SALT environment variable is required in production.'); })()
  : 'kotsafe-dev-salt-2026');

// In-memory license registry and device seat tracker
const registeredLicenses = new Map([
  [
    'KOT-PRO-ABCD1234-EF56',
    {
      plan: 'pro',
      maxSeats: 6,
      expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      activeDevices: new Set(),
      status: 'active',
    },
  ],
  [
    'KOT-PRO-DEMO1234-ABCD',
    {
      plan: 'pro',
      maxSeats: 6,
      expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      activeDevices: new Set(),
      status: 'active',
    },
  ],
  [
    'KOT-ENT-CORP9999-WXYZ',
    {
      plan: 'enterprise',
      maxSeats: 50,
      expiresAt: new Date(Date.now() + 730 * 86400000).toISOString(),
      activeDevices: new Set(),
      status: 'active',
    },
  ],
  [
    'KOT-PRO-EXPIRED0-0000',
    {
      plan: 'pro',
      maxSeats: 6,
      expiresAt: new Date(Date.now() - 5 * 86400000).toISOString(),
      activeDevices: new Set(),
      status: 'expired',
    },
  ],
  [
    'KOT-PRO-FULLSEAT-1111',
    {
      plan: 'pro',
      maxSeats: 2,
      expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      activeDevices: new Set(['seat-device-1', 'seat-device-2']),
      status: 'active',
    },
  ],
  [
    'KOT-PRO-REVOKED0-9999',
    {
      plan: 'pro',
      maxSeats: 6,
      expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
      activeDevices: new Set(),
      status: 'revoked',
    },
  ],
]);

// IP rate limiter: 5 requests per minute
const rateLimitMap = new Map();

// Short-lived, single-use phone-to-TV pairing sessions. Production deployments with more than
// one relay instance must back this map with Redis/Firestore using the same TTL and atomic
// claim semantics; it is intentionally never exposed through a read endpoint.
const TV_LINK_TTL_MS = 10 * 60 * 1000;
const tvLinkSessions = new Map();

function isRateLimited(ip) {
  const now = Date.now();
  const windowMs = 60 * 1000;
  let timestamps = rateLimitMap.get(ip) || [];
  timestamps = timestamps.filter(t => now - t < windowMs);
  if (timestamps.length >= 20) {
    return true;
  }
  timestamps.push(now);
  rateLimitMap.set(ip, timestamps);
  return false;
}

function cleanupTvLinkSessions() {
  const now = Date.now();
  for (const [sessionId, session] of tvLinkSessions.entries()) {
    if (session.expiresAt <= now) tvLinkSessions.delete(sessionId);
  }
}

function randomUrlToken(byteLength) {
  return crypto.randomBytes(byteLength).toString('base64url');
}

function hashSecret(secret) {
  return crypto.createHash('sha256').update(secret, 'utf8').digest();
}

function hasMatchingDeviceCode(session, suppliedCode) {
  if (typeof suppliedCode !== 'string' || suppliedCode.length < 16) return false;
  const suppliedHash = hashSecret(suppliedCode);
  return suppliedHash.length === session.deviceCodeHash.length
    && crypto.timingSafeEqual(suppliedHash, session.deviceCodeHash);
}

function toDisplayCode() {
  const raw = crypto.randomBytes(5).toString('hex').toUpperCase();
  return `${raw.slice(0, 5)}-${raw.slice(5)}`;
}

function safeDeviceName(value) {
  return String(value || 'KotSafe TV').replace(/[\u0000-\u001F\u007F]/g, '').trim().slice(0, 80) || 'KotSafe TV';
}

function getFirebaseAdminAuth() {
  if (getApps().length === 0) {
    const suppliedServiceAccount = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
    if (suppliedServiceAccount) {
      initializeApp({ credential: cert(JSON.parse(suppliedServiceAccount)) });
    } else {
      // Cloud Run/Functions uses Application Default Credentials. Local deployment must set
      // GOOGLE_APPLICATION_CREDENTIALS or FIREBASE_SERVICE_ACCOUNT_JSON; never ship either to an app.
      initializeApp({ credential: applicationDefault() });
    }
  }
  return getAuth();
}

function getEntitlement(decodedToken) {
  const rawTier = String(decodedToken.kotsafePlan || decodedToken.plan || 'none').trim().toUpperCase();
  const tier = rawTier === 'ENTERPRISE' ? 'ENTERPRISE' : rawTier === 'PRO' ? 'PRO' : 'NONE';
  const rawExpiry = decodedToken.licenseExpiresAt;
  let entitlementExpiresAt = 0;
  if (typeof rawExpiry === 'number' || typeof rawExpiry === 'string') {
    const parsed = Number(rawExpiry);
    if (Number.isFinite(parsed) && parsed > 0) {
      entitlementExpiresAt = parsed < 100000000000 ? parsed * 1000 : parsed;
    }
  }
  const unexpired = entitlementExpiresAt === 0 || Date.now() < entitlementExpiresAt;
  const explicitP2p = decodedToken.p2p === true || decodedToken.p2pEntitled === true;
  return {
    tier,
    entitlementExpiresAt,
    p2pEntitled: unexpired && (explicitP2p || tier === 'PRO' || tier === 'ENTERPRISE'),
  };
}

function readBearerToken(header) {
  if (typeof header !== 'string') return '';
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match ? match[1].trim() : '';
}

let ephemeralDevPrivateKey = null;

function getPrivateKeyPem() {
  if (process.env.LICENSE_PRIVATE_KEY) {
    return process.env.LICENSE_PRIVATE_KEY;
  }
  if (process.env.NODE_ENV === 'production') {
    throw new Error('FATAL: LICENSE_PRIVATE_KEY environment variable is required in production.');
  }
  if (!ephemeralDevPrivateKey) {
    console.warn('[KotSafe Backend] NOTICE: LICENSE_PRIVATE_KEY not set. Using ephemeral in-memory ECDSA key for local development.');
    const { privateKey } = crypto.generateKeyPairSync('ec', {
      namedCurve: 'prime256v1',
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
    });
    ephemeralDevPrivateKey = privateKey;
  }
  return ephemeralDevPrivateKey;
}

function computeSignature(payload, deviceId) {
  const expires = payload.expiresAt || '';
  const used = payload.seats?.used ?? 0;
  const max = payload.seats?.max ?? 0;
  const canonical = `${payload.status}:${payload.plan}:${expires}:${used}:${max}:${deviceId}`;

  try {
    const signer = crypto.createSign('SHA256');
    signer.update(canonical);
    // IEEE-P1363 produces 64-byte raw signature (128 hex chars) natively verifiable by Web Crypto API
    return signer.sign({ key: getPrivateKeyPem(), dsaEncoding: 'ieee-p1363' }).toString('hex').toUpperCase();
  } catch (err) {
    console.warn('[KotSafe Backend] ECDSA signing failed, falling back to HMAC:', err);
    return crypto.createHmac('sha256', SALT).update(canonical).digest('hex').toUpperCase();
  }
}

function sendJson(res, statusCode, data, headers = {}) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept, X-Client-Version, Authorization',
    ...headers,
  });
  res.end(JSON.stringify(data));
}

const server = http.createServer((req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Accept, X-Client-Version, Authorization',
    });
    return res.end();
  }

  const clientIp = req.socket.remoteAddress || '127.0.0.1';
  if (isRateLimited(clientIp)) {
    return sendJson(
      res,
      429,
      {
        status: 'invalid',
        plan: 'freemium',
        expiresAt: null,
        seats: { used: 0, max: 0 },
        signature: '',
        errorCode: 'RATE_LIMITED',
      },
      { 'Retry-After': '60' }
    );
  }

  const MAX_BODY_SIZE = 64 * 1024; // 64 KB limit
  let bodyData = '';
  let bodyTooLarge = false;

  req.on('data', chunk => {
    if (bodyTooLarge) return;
    bodyData += chunk;
    if (bodyData.length > MAX_BODY_SIZE) {
      bodyTooLarge = true;
      sendJson(res, 413, {
        status: 'invalid',
        errorCode: 'PAYLOAD_TOO_LARGE',
        message: 'Payload exceeds maximum allowed size (64KB)'
      });
      req.destroy();
    }
  });

  req.on('end', async () => {
    if (bodyTooLarge) return;
    let body = {};
    try {
      if (bodyData) body = JSON.parse(bodyData);
    } catch {
      return sendJson(res, 400, {
        status: 'invalid',
        errorCode: 'INVALID_FORMAT',
      });
    }

    const { key, deviceId } = body;

    // Phone-first TV link. The QR contains only a random, short-lived device code; the phone
    // must additionally present a verified Firebase ID token. The TV receives a one-time custom
    // token after approval, never the phone's password, Firebase ID token, or licence key.
    if (req.url === '/v1/tv-auth/start' && req.method === 'POST') {
      cleanupTvLinkSessions();
      const sessionId = randomUrlToken(24);
      const deviceCode = randomUrlToken(32);
      const expiresAt = Date.now() + TV_LINK_TTL_MS;
      tvLinkSessions.set(sessionId, {
        deviceCodeHash: hashSecret(deviceCode),
        deviceName: safeDeviceName(body.deviceName),
        expiresAt,
        approved: false,
      });
      const linkUri = `kotsafe://tv-auth?sid=${encodeURIComponent(sessionId)}&code=${encodeURIComponent(deviceCode)}`;
      return sendJson(res, 201, {
        sessionId,
        deviceCode,
        displayCode: toDisplayCode(),
        linkUri,
        expiresAt,
        pollIntervalSeconds: 4,
      });
    }

    if (req.url === '/v1/tv-auth/approve' && req.method === 'POST') {
      cleanupTvLinkSessions();
      const session = tvLinkSessions.get(body.sessionId);
      if (!session || !hasMatchingDeviceCode(session, body.deviceCode)) {
        return sendJson(res, 404, { error: 'TV link not found or expired' });
      }
      const idToken = readBearerToken(req.headers.authorization);
      if (!idToken) return sendJson(res, 401, { error: 'KotSafe account sign-in is required' });
      try {
        const decoded = await getFirebaseAdminAuth().verifyIdToken(idToken, true);
        if (session.approved && session.uid !== decoded.uid) {
          return sendJson(res, 409, { error: 'This TV link was already approved by another account' });
        }
        const entitlement = getEntitlement(decoded);
        session.approved = true;
        session.uid = decoded.uid;
        session.email = typeof decoded.email === 'string' ? decoded.email : '';
        session.tier = entitlement.tier;
        session.p2pEntitled = entitlement.p2pEntitled;
        session.entitlementExpiresAt = entitlement.entitlementExpiresAt;
        return sendJson(res, 200, {
          message: `${session.deviceName} approved. Return to your TV to finish signing in.`,
          p2pEntitled: session.p2pEntitled,
        });
      } catch (error) {
        console.warn('[KotSafe TV Auth] Firebase token verification failed:', error?.message || error);
        return sendJson(res, 401, { error: 'Your KotSafe sign-in could not be verified' });
      }
    }

    if (req.url === '/v1/tv-auth/exchange' && req.method === 'POST') {
      cleanupTvLinkSessions();
      const session = tvLinkSessions.get(body.sessionId);
      if (!session || !hasMatchingDeviceCode(session, body.deviceCode)) {
        return sendJson(res, 404, { error: 'TV link not found or expired' });
      }
      if (!session.approved) {
        return sendJson(res, 428, { error: 'authorization_pending', message: 'Waiting for phone approval' });
      }
      try {
        const customClaims = {
          kotsafePlan: session.tier,
          p2p: session.p2pEntitled,
        };
        if (session.entitlementExpiresAt > 0) customClaims.licenseExpiresAt = session.entitlementExpiresAt;
        const customToken = await getFirebaseAdminAuth().createCustomToken(session.uid, customClaims);
        tvLinkSessions.delete(body.sessionId); // One exchange only.
        return sendJson(res, 200, {
          customToken,
          email: session.email,
          tier: session.tier,
          p2pEntitled: session.p2pEntitled,
          entitlementExpiresAt: session.entitlementExpiresAt,
        });
      } catch (error) {
        console.error('[KotSafe TV Auth] Could not mint TV custom token:', error?.message || error);
        return sendJson(res, 503, { error: 'KotSafe TV sign-in service is not configured' });
      }
    }

    // 1. POST /license/activate
    if (req.url === '/license/activate' && req.method === 'POST') {
      if (!key || !deviceId) {
        return sendJson(res, 400, {
          status: 'invalid',
          plan: 'freemium',
          expiresAt: null,
          seats: { used: 0, max: 0 },
          signature: '',
          errorCode: 'INVALID_FORMAT',
        });
      }

      const lic = registeredLicenses.get(key.toUpperCase());
      if (!lic) {
        // Dynamic demo key generation is strictly forbidden in production and only allowed when explicitly enabled
        if (process.env.NODE_ENV !== 'production' && process.env.ALLOW_DYNAMIC_DEMO_KEYS === 'true') {
          if (key.startsWith('KOT-PRO-') || key.startsWith('KOT-ENT-')) {
            const plan = key.includes('ENT') ? 'enterprise' : 'pro';
            const maxSeats = plan === 'enterprise' ? 25 : 6;
            const expiresAt = new Date(Date.now() + 365 * 86400000).toISOString();
            const dynamicLic = {
              plan,
              maxSeats,
              expiresAt,
              activeDevices: new Set([deviceId]),
              status: 'active',
            };
            registeredLicenses.set(key.toUpperCase(), dynamicLic);

            const payload = {
              status: 'active',
              plan,
              expiresAt,
              seats: { used: 1, max: maxSeats },
            };
            const signature = computeSignature(payload, deviceId);
            return sendJson(res, 200, { ...payload, signature, serverTime: Date.now() });
          }
        }

        return sendJson(res, 404, {
          status: 'invalid',
          plan: 'freemium',
          expiresAt: null,
          seats: { used: 0, max: 0 },
          signature: '',
          errorCode: 'KEY_NOT_FOUND',
        });
      }

      if (lic.status === 'revoked') {
        return sendJson(res, 403, {
          status: 'revoked',
          plan: lic.plan,
          expiresAt: lic.expiresAt,
          seats: { used: lic.activeDevices.size, max: lic.maxSeats },
          signature: '',
          errorCode: 'REVOKED',
        });
      }

      if (lic.status === 'expired' || (lic.expiresAt && new Date(lic.expiresAt) < new Date())) {
        return sendJson(res, 400, {
          status: 'expired',
          plan: lic.plan,
          expiresAt: lic.expiresAt,
          seats: { used: lic.activeDevices.size, max: lic.maxSeats },
          signature: '',
          errorCode: 'EXPIRED',
        });
      }

      if (lic.activeDevices.size >= lic.maxSeats && !lic.activeDevices.has(deviceId)) {
        return sendJson(res, 400, {
          status: 'invalid',
          plan: lic.plan,
          expiresAt: lic.expiresAt,
          seats: { used: lic.activeDevices.size, max: lic.maxSeats },
          signature: '',
          errorCode: 'SEAT_LIMIT',
        });
      }

      lic.activeDevices.add(deviceId);
      const payload = {
        status: 'active',
        plan: lic.plan,
        expiresAt: lic.expiresAt,
        seats: { used: lic.activeDevices.size, max: lic.maxSeats },
      };
      const signature = computeSignature(payload, deviceId);
      return sendJson(res, 200, { ...payload, signature, serverTime: Date.now() });
    }

    // 2. POST /license/validate
    if (req.url === '/license/validate' && req.method === 'POST') {
      const lic = registeredLicenses.get((key || '').toUpperCase());
      if (!lic) {
        return sendJson(res, 404, {
          status: 'invalid',
          plan: 'freemium',
          expiresAt: null,
          seats: { used: 0, max: 0 },
          signature: '',
          errorCode: 'KEY_NOT_FOUND',
        });
      }

      if (lic.status === 'revoked') {
        return sendJson(res, 403, {
          status: 'revoked',
          plan: lic.plan,
          expiresAt: lic.expiresAt,
          seats: { used: lic.activeDevices.size, max: lic.maxSeats },
          signature: '',
          errorCode: 'REVOKED',
        });
      }

      if (lic.status === 'expired' || (lic.expiresAt && new Date(lic.expiresAt) < new Date())) {
        return sendJson(res, 400, {
          status: 'expired',
          plan: lic.plan,
          expiresAt: lic.expiresAt,
          seats: { used: lic.activeDevices.size, max: lic.maxSeats },
          signature: '',
          errorCode: 'EXPIRED',
        });
      }

      const payload = {
        status: 'active',
        plan: lic.plan,
        expiresAt: lic.expiresAt,
        seats: { used: Math.max(1, lic.activeDevices.size), max: lic.maxSeats },
      };
      const signature = computeSignature(payload, deviceId || 'device');
      return sendJson(res, 200, { ...payload, signature, serverTime: Date.now() });
    }

    // 3. POST /license/deactivate
    if (req.url === '/license/deactivate' && req.method === 'POST') {
      const lic = registeredLicenses.get((key || '').toUpperCase());
      if (lic) {
        lic.activeDevices.delete(deviceId);
      }
      return sendJson(res, 200, {
        status: 'invalid',
        plan: 'freemium',
        expiresAt: null,
        seats: { used: lic ? lic.activeDevices.size : 0, max: lic ? lic.maxSeats : 0 },
        signature: '',
      });
    }

    // 404 Not Found
    return sendJson(res, 404, { error: 'Not Found' });
  });
});

server.listen(PORT, () => {
  console.log(`[KotSafe License Server] Listening on http://localhost:${PORT}`);
});
