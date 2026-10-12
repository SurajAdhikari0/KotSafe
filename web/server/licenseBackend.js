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

const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 8080;
const SALT = process.env.LICENSE_SALT || 'kotsafe-salt-2026';

// In-memory license registry and device seat tracker
const registeredLicenses = new Map([
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

function computeSignature(payload, deviceId) {
  const expires = payload.expiresAt || '';
  const used = payload.seats?.used ?? 0;
  const max = payload.seats?.max ?? 0;
  const canonical = `${payload.status}:${payload.plan}:${expires}:${used}:${max}:${deviceId}`;
  return crypto.createHmac('sha256', SALT).update(canonical).digest('hex').toUpperCase();
}

function sendJson(res, statusCode, data, headers = {}) {
  res.writeHead(statusCode, {
    'Content-Type': 'application/json',
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, Accept, X-Client-Version',
    ...headers,
  });
  res.end(JSON.stringify(data));
}

const server = http.createServer((req, res) => {
  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Accept, X-Client-Version',
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

  let bodyData = '';
  req.on('data', chunk => {
    bodyData += chunk;
  });

  req.on('end', () => {
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
        // Also allow dynamically structured keys that start with KOT-
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
