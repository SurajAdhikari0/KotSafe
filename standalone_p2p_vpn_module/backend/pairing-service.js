'use strict';

// Small control-plane reference. It issues short-lived relay tokens but never
// sees packet plaintext. Run it behind HTTPS and replace MemoryPairStore with
// a transactional, encrypted database before operating more than one replica.
const crypto = require('crypto');
const http = require('http');
const { mintSessionToken, verifySessionToken } = require('../server/session-token');

const PORT = Number.parseInt(process.env.CONTROL_PORT || '8081', 10);
const HOST = process.env.CONTROL_HOST || '127.0.0.1';
const SIGNING_KEY = process.env.RELAY_SIGNING_KEY;
const CONTROL_API_TOKEN = process.env.CONTROL_API_TOKEN;
const TURN_SHARED_SECRET = process.env.TURN_SHARED_SECRET;
const TURN_HOST = process.env.TURN_HOST;
const CONTROL_PUBLIC_URL = process.env.CONTROL_PUBLIC_URL;
const PAIRING_TTL_SECONDS = 5 * 60;
const SESSION_TTL_SECONDS = 10 * 60;
const TURN_TTL_SECONDS = 10 * 60;

function randomId(bytes) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function sha256(value) {
  return crypto.createHash('sha256').update(value).digest('base64url');
}

class MemoryPairStore {
  constructor() { this.pairs = new Map(); }

  create(exitDeviceId) {
    const room = randomId(18);
    const pairingSecret = randomId(32);
    const pair = {
      room,
      exitDeviceId,
      secretHash: sha256(pairingSecret),
      expiresAt: Date.now() + PAIRING_TTL_SECONDS * 1000,
      claimed: false
    };
    this.pairs.set(room, pair);
    return { pair, pairingSecret };
  }

  claim(room, pairingSecret, clientDeviceId) {
    const pair = this.pairs.get(room);
    if (!pair || pair.expiresAt < Date.now() || pair.claimed || sha256(pairingSecret) !== pair.secretHash) {
      throw new Error('invalid or expired pairing');
    }
    pair.claimed = true;
    return pair;
  }

  sweep() {
    const now = Date.now();
    for (const [room, pair] of this.pairs) if (pair.expiresAt < now) this.pairs.delete(room);
  }
}

// Signalling data is short lived and contains network candidates only. Packet
// payloads and tunnel keys never pass through this control-plane store.
class CandidateStore {
  constructor(ttlMs = 90_000) {
    this.ttlMs = ttlMs;
    this.byRoom = new Map();
  }

  publish(claims, candidate) {
    validateCandidate(candidate);
    const expiresAt = Date.now() + this.ttlMs;
    let entries = this.byRoom.get(claims.room);
    if (!entries) {
      entries = new Map();
      this.byRoom.set(claims.room, entries);
    }
    entries.set(`${claims.role}:${claims.deviceId}`, { candidate, expiresAt });
  }

  peerCandidates(claims) {
    const entries = this.byRoom.get(claims.room);
    if (!entries) return [];
    const now = Date.now();
    const result = [];
    for (const [key, entry] of entries) {
      if (entry.expiresAt < now) {
        entries.delete(key);
      } else if (!key.startsWith(`${claims.role}:`)) {
        result.push(entry.candidate);
      }
    }
    if (entries.size === 0) this.byRoom.delete(claims.room);
    return result;
  }
}

// Pairing confidentiality comes from the high-entropy QR secret, not a global
// APK secret. This limiter only bounds anonymous room-creation abuse; replace
// it with durable, account/device-aware rate limiting in a multi-node service.
class PairingRateLimiter {
  constructor({ limit = 5, windowMs = 15 * 60 * 1000 } = {}) {
    this.limit = limit;
    this.windowMs = windowMs;
    this.entries = new Map();
  }

  allow(source, now = Date.now()) {
    const prior = this.entries.get(source);
    if (!prior || prior.resetAt <= now) {
      this.entries.set(source, { count: 1, resetAt: now + this.windowMs });
      return true;
    }
    if (prior.count >= this.limit) return false;
    prior.count += 1;
    return true;
  }
}

function validateCandidate(candidate) {
  if (!candidate || typeof candidate !== 'object' || Array.isArray(candidate)) throw new Error('invalid candidate');
  if (!['host', 'srflx'].includes(candidate.type)) throw new Error('invalid candidate type');
  if (typeof candidate.address !== 'string' || candidate.address.length < 1 || candidate.address.length > 253) {
    throw new Error('invalid candidate address');
  }
  if (!Number.isInteger(candidate.port) || candidate.port < 1 || candidate.port > 65535) {
    throw new Error('invalid candidate port');
  }
}

function send(response, status, body) {
  response.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  response.end(status === 204 ? undefined : JSON.stringify(body));
}

function readJson(request) {
  return new Promise((resolve, reject) => {
    let raw = '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => {
      raw += chunk;
      if (raw.length > 16 * 1024) request.destroy(new Error('body too large'));
    });
    request.on('end', () => {
      try { resolve(JSON.parse(raw || '{}')); } catch { reject(new Error('invalid JSON')); }
    });
    request.on('error', reject);
  });
}

function requireId(value, name) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]{8,96}$/.test(value)) {
    throw new Error(`invalid ${name}`);
  }
}

function createTurnCredentials(turnSharedSecret, turnHost, claims, nowSeconds = Math.floor(Date.now() / 1000)) {
  if (typeof turnSharedSecret !== 'string' || Buffer.byteLength(turnSharedSecret) < 32) {
    throw new Error('TURN_SHARED_SECRET must contain at least 32 bytes');
  }
  if (typeof turnHost !== 'string' || !/^[A-Za-z0-9.-]{1,253}$/.test(turnHost)) {
    throw new Error('TURN_HOST must be a DNS name or IP literal');
  }
  const username = `${nowSeconds + TURN_TTL_SECONDS}:${claims.deviceId}`;
  const credential = crypto.createHmac('sha1', turnSharedSecret).update(username).digest('base64');
  return {
    username,
    credential,
    expiresAt: new Date((nowSeconds + TURN_TTL_SECONDS) * 1000).toISOString(),
    urls: [
      `turn:${turnHost}:3478?transport=udp`,
      `turns:${turnHost}:5349?transport=tcp`
    ]
  };
}

function bearerClaims(request, signingKey) {
  const authorization = request.headers.authorization || '';
  const match = authorization.match(/^Bearer (.+)$/);
  if (!match) return null;
  try { return verifySessionToken(signingKey, match[1]); }
  catch { return null; }
}

function sourceKey(request) {
  // The control container is published only to host loopback and should sit
  // behind a trusted reverse proxy. Do not expose it directly to the Internet.
  const forwarded = request.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.length <= 128) return forwarded.split(',', 1)[0].trim();
  return request.socket.remoteAddress || 'unknown';
}

function createPairingResponse(store, signingKey, controlPublicUrl, exitDeviceId) {
  const { pair, pairingSecret } = store.create(exitDeviceId);
  const exitToken = mintSessionToken(signingKey, {
    room: pair.room, role: 'exit', deviceId: pair.exitDeviceId
  }, SESSION_TTL_SECONDS);
  return {
    room: pair.room,
    pairingSecret,
    expiresAt: new Date(pair.expiresAt).toISOString(),
    exitToken,
    // QR contains pairing material, never a privileged server/admin secret.
    qr: { version: 2, room: pair.room, pairingSecret, controlUrl: controlPublicUrl }
  };
}

function createControlServer({
  signingKey, controlApiToken, turnSharedSecret, turnHost,
  controlPublicUrl, store = new MemoryPairStore(), candidateStore = new CandidateStore(),
  pairingRateLimiter = new PairingRateLimiter()
}) {
  if (!signingKey || Buffer.byteLength(signingKey) < 32) throw new Error('RELAY_SIGNING_KEY must contain at least 32 bytes');
  if (controlApiToken && Buffer.byteLength(controlApiToken) < 24) throw new Error('CONTROL_API_TOKEN must contain at least 24 bytes');
  if (typeof controlPublicUrl !== 'string' || !/^https:\/\/[A-Za-z0-9.-]+(?::\d+)?(?:\/.*)?$/.test(controlPublicUrl)) {
    throw new Error('CONTROL_PUBLIC_URL must be an https URL');
  }

  return http.createServer(async (request, response) => {
    try {
      if (request.method === 'GET' && request.url === '/healthz') return send(response, 200, { ok: true });
      if (request.url === '/v1/candidates') {
        const claims = bearerClaims(request, signingKey);
        if (!claims) return send(response, 401, { error: 'unauthorized' });
        if (request.method === 'GET') return send(response, 200, { candidates: candidateStore.peerCandidates(claims) });
        if (request.method === 'POST') {
          const body = await readJson(request);
          candidateStore.publish(claims, body.candidate);
          return send(response, 204, {});
        }
        return send(response, 405, { error: 'method_not_allowed' });
      }
      if (request.url === '/v1/turn-credentials' && request.method === 'GET') {
        const claims = bearerClaims(request, signingKey);
        if (!claims) return send(response, 401, { error: 'unauthorized' });
        if (!turnSharedSecret || !turnHost) return send(response, 503, { error: 'turn_not_configured' });
        return send(response, 200, createTurnCredentials(turnSharedSecret, turnHost, claims));
      }
      if (request.method !== 'POST') return send(response, 404, { error: 'not_found' });
      const body = await readJson(request);

      if (request.url === '/v1/pairings') {
        const isAdmin = Boolean(controlApiToken) && request.headers.authorization === `Bearer ${controlApiToken}`;
        if (!isAdmin && !pairingRateLimiter.allow(sourceKey(request))) {
          return send(response, 429, { error: 'pairing_rate_limited' });
        }
        requireId(body.exitDeviceId, 'exitDeviceId');
        return send(response, 201, createPairingResponse(store, signingKey, controlPublicUrl, body.exitDeviceId));
      }

      const claim = request.url.match(/^\/v1\/pairings\/([A-Za-z0-9_-]{16,96})\/claim$/);
      if (claim) {
        requireId(body.clientDeviceId, 'clientDeviceId');
        if (typeof body.pairingSecret !== 'string' || body.pairingSecret.length < 40) {
          throw new Error('invalid pairingSecret');
        }
        const pair = store.claim(claim[1], body.pairingSecret, body.clientDeviceId);
        const clientToken = mintSessionToken(signingKey, {
          room: pair.room, role: 'client', deviceId: body.clientDeviceId
        }, SESSION_TTL_SECONDS);
        return send(response, 200, { room: pair.room, clientToken, expiresInSeconds: SESSION_TTL_SECONDS });
      }
      return send(response, 404, { error: 'not_found' });
    } catch (error) {
      return send(response, 400, { error: error.message });
    }
  });
}

if (require.main === module) {
  const server = createControlServer({
    signingKey: SIGNING_KEY, controlApiToken: CONTROL_API_TOKEN,
    turnSharedSecret: TURN_SHARED_SECRET, turnHost: TURN_HOST, controlPublicUrl: CONTROL_PUBLIC_URL
  });
  server.listen(PORT, HOST, () => console.log(`pairing control API listening on ${HOST}:${PORT}`));
  setInterval(() => {}, 2 ** 31 - 1).unref();
}

module.exports = {
  CandidateStore, MemoryPairStore, PairingRateLimiter, createControlServer, createTurnCredentials
};
