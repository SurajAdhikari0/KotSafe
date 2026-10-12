'use strict';

const crypto = require('crypto');

function b64url(input) {
  return Buffer.from(input).toString('base64url');
}

function timingSafeEqual(left, right) {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function assertSigningKey(signingKey) {
  if (typeof signingKey !== 'string' || Buffer.byteLength(signingKey, 'utf8') < 32) {
    throw new Error('RELAY_SIGNING_KEY must contain at least 32 bytes');
  }
}

function mintSessionToken(signingKey, claims, ttlSeconds = 600) {
  assertSigningKey(signingKey);
  const now = Math.floor(Date.now() / 1000);
  const payload = {
    v: 1,
    room: claims.room,
    role: claims.role,
    deviceId: claims.deviceId,
    iat: now,
    exp: now + ttlSeconds,
    nonce: crypto.randomBytes(12).toString('base64url')
  };
  if (!/^[A-Za-z0-9_-]{16,96}$/.test(payload.room)) throw new Error('invalid room');
  if (!['client', 'exit'].includes(payload.role)) throw new Error('invalid role');
  if (!/^[A-Za-z0-9_-]{8,96}$/.test(payload.deviceId)) throw new Error('invalid deviceId');
  const encoded = b64url(JSON.stringify(payload));
  const mac = crypto.createHmac('sha256', signingKey).update(encoded).digest('base64url');
  return `${encoded}.${mac}`;
}

function verifySessionToken(signingKey, token) {
  assertSigningKey(signingKey);
  if (typeof token !== 'string') throw new Error('missing session token');
  const [encoded, receivedMac, extra] = token.split('.');
  if (!encoded || !receivedMac || extra) throw new Error('invalid session token format');
  const expectedMac = crypto.createHmac('sha256', signingKey).update(encoded).digest('base64url');
  if (!timingSafeEqual(receivedMac, expectedMac)) throw new Error('invalid session token signature');
  let claims;
  try {
    claims = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
  } catch {
    throw new Error('invalid session token payload');
  }
  if (claims.v !== 1 || !['client', 'exit'].includes(claims.role) ||
      typeof claims.room !== 'string' || typeof claims.deviceId !== 'string' ||
      !Number.isInteger(claims.exp) || claims.exp <= Math.floor(Date.now() / 1000)) {
    throw new Error('expired or invalid session token');
  }
  return claims;
}

module.exports = { mintSessionToken, verifySessionToken };
