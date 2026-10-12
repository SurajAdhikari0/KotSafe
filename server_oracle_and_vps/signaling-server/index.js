/*
 * Unified Pairing Control & Multiplexed Signaling Relay Server
 * KotSafe Cyber Security Project (v2.0)
 *
 * Implements:
 * 1. REST Control API:
 *    - GET /health, GET /healthz
 *    - POST /v1/pairings (Issues v2 QR bundle, room, pairingSecret, exitToken)
 *    - POST /v1/pairings/:room/claim (Validates pairingSecret, issues clientToken)
 *    - GET/POST /v1/candidates (ICE candidate signaling)
 *    - GET /v1/turn-credentials (STUN/TURN config)
 *    - POST /pairing, DELETE /pairing/:token (v1 backward compatibility)
 * 2. High-Performance Multiplexed WebSocket Relay (/ws):
 *    - register_host / publish (Exit node candidate registration)
 *    - subscribe (Client candidate synchronization)
 *    - pipe_open / pipe_ack / pipe_close / pipe_reject (Point-to-point stream binding)
 *    - Binary 0xA7 data frames (High throughput, zero GC overhead)
 *    - Sliding TTL on activity (live connections never drop prematurely)
 */

'use strict';

const http = require('http');
const crypto = require('crypto');
const WebSocket = require('ws');

const PORT = parseInt(process.env.CONTROL_PORT || process.env.PORT, 10) || 8081;
const HOST = process.env.CONTROL_HOST || '0.0.0.0';
const SHARED_SECRET = process.env.SHARED_SECRET || process.env.RELAY_SIGNING_KEY || 'kotsafe-p2p-secret-key-32-chars-minimum';
const PAIRING_TTL_SECONDS = parseInt(process.env.PAIRING_TTL_SECONDS, 10) || 86400;
const RATE_LIMIT_MAX = parseInt(process.env.RATE_LIMIT_MAX, 10) || 120;
const RATE_LIMIT_WINDOW_MS = 60 * 1000;
const MAX_CANDIDATES_PER_PAIRING = 16;
const MAX_STREAMS_PER_PAIRING = 512;
const MAX_TOTAL_PAIRINGS = 10000;
const SEND_HIGH_WATER = 4 * 1024 * 1024;
const CONTROL_PUBLIC_URL = process.env.CONTROL_PUBLIC_URL || 'https://couples-weekly-functionality-goal.trycloudflare.com';

const MAGIC = 0xa7;
const OP_DATA = 0x01;
const DB_FILE = process.env.PAIRINGS_DB || '/tmp/pairings_db.json';
const fs = require('fs');

const pairings = new Map();         // token -> pairing object
const pairingsByRoom = new Map();   // room -> pairing object
const rateLimits = new Map();       // ip -> { count, windowStart }

function savePairings() {
  try {
    const list = [];
    for (const p of pairingsByRoom.values()) {
      if (p.expiresAt > Date.now()) {
        list.push({
          token: p.token,
          room: p.room,
          pairingSecret: p.pairingSecret,
          exitDeviceId: p.exitDeviceId,
          exitToken: p.exitToken,
          clientToken: p.clientToken,
          clientDeviceId: p.clientDeviceId,
          candidates: p.candidates,
          updatedAt: p.updatedAt,
          expiresAt: p.expiresAt,
        });
      }
    }
    fs.writeFileSync(DB_FILE, JSON.stringify(list), 'utf8');
  } catch (err) {
    console.error('Failed to save pairings to disk:', err.message);
  }
}

function loadPairings() {
  try {
    if (!fs.existsSync(DB_FILE)) return;
    const data = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    const now = Date.now();
    for (const item of data) {
      if (item.expiresAt > now) {
        const p = {
          ...item,
          subscribers: new Set(),
          hostSockets: new Set(),
          streams: new Map(),
        };
        if (p.exitToken) pairings.set(p.exitToken, p);
        if (p.clientToken) pairings.set(p.clientToken, p);
        if (p.token) pairings.set(p.token, p);
        if (p.room) pairingsByRoom.set(p.room, p);
      }
    }
    console.log(`Loaded ${pairingsByRoom.size} persistent pairings from ${DB_FILE}`);
  } catch (err) {
    console.error('Failed to load pairings from disk:', err.message);
  }
}

loadPairings();

function isRateLimited(ip) {
  const now = Date.now();
  let entry = rateLimits.get(ip);
  if (!entry || now - entry.windowStart > RATE_LIMIT_WINDOW_MS) {
    entry = { count: 0, windowStart: now };
    rateLimits.set(ip, entry);
  }
  entry.count += 1;
  return entry.count > RATE_LIMIT_MAX;
}

function generateToken() {
  return crypto.randomBytes(16).toString('hex');
}

function sanitizeCandidates(raw) {
  if (!Array.isArray(raw)) return [];
  return raw
    .filter((c) => c && typeof c.host === 'string' && typeof c.port === 'number')
    .slice(0, MAX_CANDIDATES_PER_PAIRING)
    .map((c) => ({
      type: ['LAN', 'GLOBAL_IPV6', 'UPNP_PUBLIC', 'STUN', 'RELAY'].includes(c.type) ? c.type : 'STUN',
      host: String(c.host).slice(0, 128),
      port: Math.max(1, Math.min(65535, c.port | 0)),
      discoveredAt: Number.isFinite(c.discoveredAt) ? c.discoveredAt : Date.now(),
    }));
}

function touchPairing(token) {
  if (typeof token !== 'string') return null;
  const p = pairings.get(token);
  if (!p) return null;
  if (Date.now() > p.expiresAt) {
    destroyPairing(p);
    return null;
  }
  p.expiresAt = Date.now() + PAIRING_TTL_SECONDS * 1000;
  return p;
}

function destroyPairing(p) {
  if (!p) return;
  for (const st of p.streams.values()) {
    safeSend(st.clientWs, JSON.stringify({ type: 'pipe_close', streamId: st.id }));
    safeSend(st.hostWs, JSON.stringify({ type: 'pipe_close', streamId: st.id }));
  }
  p.streams.clear();
  if (p.exitToken) pairings.delete(p.exitToken);
  if (p.clientToken) pairings.delete(p.clientToken);
  if (p.token) pairings.delete(p.token);
  if (p.room) pairingsByRoom.delete(p.room);
}

function safeSend(ws, payload) {
  if (!ws || ws.readyState !== WebSocket.OPEN) return false;
  if (ws.bufferedAmount > SEND_HIGH_WATER) return false;
  try {
    ws.send(payload, { binary: Buffer.isBuffer(payload) });
    return true;
  } catch {
    return false;
  }
}

function pickHost(p) {
  let best = null;
  for (const hws of p.hostSockets) {
    if (hws.readyState !== WebSocket.OPEN) continue;
    if (best === null || hws.bufferedAmount < best.bufferedAmount) best = hws;
  }
  return best;
}

function readStreamId(buf) {
  const h = buf.toString('hex', 2, 18);
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
}

function closeStream(p, streamId, notify) {
  const st = p.streams.get(streamId);
  if (!st) return;
  p.streams.delete(streamId);
  if (notify) {
    const msg = JSON.stringify({ type: 'pipe_close', streamId });
    safeSend(st.clientWs === notify ? st.hostWs : st.clientWs, msg);
  }
}

function readJson(req) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.setEncoding('utf8');
    req.on('data', (chunk) => {
      body += chunk;
      if (body.length > 64 * 1024) req.destroy(new Error('body too large'));
    });
    req.on('end', () => {
      try { resolve(JSON.parse(body || '{}')); } catch (e) { reject(new Error('invalid JSON')); }
    });
    req.on('error', reject);
  });
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff'
  });
  res.end(JSON.stringify(data));
}

// ---------------------------------------------------------------- HTTP Server
const server = http.createServer(async (req, res) => {
  const ip = req.socket.remoteAddress || 'unknown';

  if (req.method === 'GET' && (req.url === '/health' || req.url === '/healthz')) {
    return sendJson(res, 200, { ok: true, version: '2.0.1', pairings: pairingsByRoom.size });
  }

  if (isRateLimited(ip)) {
    return sendJson(res, 429, { error: 'rate_limited' });
  }

  // POST /v1/pairings - Create pairing bundle (v2 QR)
  if (req.method === 'POST' && req.url === '/v1/pairings') {
    try {
      const body = await readJson(req);
      if (pairingsByRoom.size >= MAX_TOTAL_PAIRINGS) {
        return sendJson(res, 503, { error: 'server_capacity_reached' });
      }

      const exitDeviceId = body.exitDeviceId || ('dev_' + generateToken().slice(0, 16));
      const room = 'room_' + generateToken().slice(0, 20);
      const pairingSecret = generateToken() + generateToken(); // 64 hex chars
      const exitToken = generateToken();
      const clientToken = generateToken();
      const expiresAt = Date.now() + PAIRING_TTL_SECONDS * 1000;

      const p = {
        token: exitToken,
        room,
        pairingSecret,
        exitDeviceId,
        exitToken,
        clientToken,
        candidates: [],
        updatedAt: Date.now(),
        expiresAt,
        subscribers: new Set(),
        hostSockets: new Set(),
        streams: new Map(),
      };

      pairings.set(exitToken, p);
      pairings.set(clientToken, p);
      pairingsByRoom.set(room, p);
      savePairings();

      console.log(`[PAIRING v2] created room=${room} exitDeviceId=${exitDeviceId}`);

      return sendJson(res, 201, {
        room,
        pairingSecret,
        exitToken,
        expiresAt: new Date(expiresAt).toISOString(),
        qr: {
          version: 2,
          room,
          pairingSecret,
          controlUrl: CONTROL_PUBLIC_URL
        }
      });
    } catch (err) {
      return sendJson(res, 400, { error: err.message });
    }
  }

  // POST /v1/pairings/:room/claim - Claim pairing from scanned QR
  const claimMatch = req.method === 'POST' && req.url.match(/^\/v1\/pairings\/([A-Za-z0-9_-]+)\/claim$/);
  if (claimMatch) {
    try {
      const body = await readJson(req);
      const room = claimMatch[1];
      const p = pairingsByRoom.get(room);
      if (!p || p.expiresAt < Date.now()) {
        return sendJson(res, 404, { error: 'pairing_not_found_or_expired' });
      }
      if (body.pairingSecret !== p.pairingSecret) {
        return sendJson(res, 403, { error: 'invalid_pairing_secret' });
      }
      p.clientDeviceId = body.clientDeviceId || ('dev_' + generateToken().slice(0, 16));
      p.expiresAt = Date.now() + PAIRING_TTL_SECONDS * 1000;
      savePairings();

      console.log(`[PAIRING v2] claimed room=${room} clientDeviceId=${p.clientDeviceId}`);

      return sendJson(res, 200, {
        room,
        clientToken: p.clientToken,
        expiresInSeconds: PAIRING_TTL_SECONDS
      });
    } catch (err) {
      return sendJson(res, 400, { error: err.message });
    }
  }

  // Candidate signaling: /v1/candidates
  if (req.url === '/v1/candidates') {
    const auth = req.headers.authorization || '';
    const match = auth.match(/^Bearer\s+(.+)$/);
    const p = match ? touchPairing(match[1].trim()) : null;
    if (!p) return sendJson(res, 401, { error: 'unauthorized' });

    if (req.method === 'GET') {
      return sendJson(res, 200, { candidates: p.candidates || [] });
    }
    if (req.method === 'POST') {
      try {
        const body = await readJson(req);
        if (body.candidate) {
          p.candidates = sanitizeCandidates([body.candidate, ...(p.candidates || [])]);
          p.updatedAt = Date.now();
        }
        res.writeHead(204);
        return res.end();
      } catch (err) {
        return sendJson(res, 400, { error: err.message });
      }
    }
  }

  // TURN credentials: /v1/turn-credentials
  if (req.url === '/v1/turn-credentials' && req.method === 'GET') {
    return sendJson(res, 200, {
      username: 'kotsafe',
      credential: 'password',
      urls: ['turn:130.210.16.110:3478?transport=udp']
    });
  }

  // Legacy POST /pairing
  if (req.method === 'POST' && req.url === '/pairing') {
    const token = generateToken();
    const expiresAt = Date.now() + PAIRING_TTL_SECONDS * 1000;
    pairings.set(token, {
      token,
      candidates: [],
      updatedAt: Date.now(),
      expiresAt,
      subscribers: new Set(),
      hostSockets: new Set(),
      streams: new Map(),
    });
    return sendJson(res, 201, { token, expiresAt });
  }

  // Legacy DELETE /pairing/:token
  const delMatch = req.method === 'DELETE' && req.url.match(/^\/pairing\/([a-f0-9]+)$/);
  if (delMatch) {
    const p = pairings.get(delMatch[1]);
    if (p) destroyPairing(p);
    return sendJson(res, 200, { revoked: Boolean(p) });
  }

  sendJson(res, 404, { error: 'not_found' });
});

// ---------------------------------------------------------------- WebSocket Relay
const wss = new WebSocket.Server({
  server,
  maxPayload: 4 * 1024 * 1024,
  perMessageDeflate: false,
});

wss.on('connection', (ws, req) => {
  ws.isAlive = true;
  ws.role = null;          // 'host' | 'client'
  ws.pairingToken = null;
  ws.on('pong', () => { ws.isAlive = true; });

  ws.on('message', (raw, isBinary) => {
    // ---- fast path: binary bulk data ------------------------------------
    if (isBinary) {
      const buf = Buffer.isBuffer(raw) ? raw : Buffer.from(raw);
      if (buf.length < 18 || buf[0] !== MAGIC || buf[1] !== OP_DATA) return;
      const p = ws.pairingToken ? touchPairing(ws.pairingToken) : null;
      if (!p) return;
      const streamId = readStreamId(buf);
      const st = p.streams.get(streamId);
      if (!st) return;
      const peer = ws === st.clientWs ? st.hostWs : ws === st.hostWs ? st.clientWs : null;
      if (!peer) return;
      if (!safeSend(peer, buf)) {
        console.warn(`[PIPE] dropping stream ${streamId}: peer over high-water mark`);
        closeStream(p, streamId, ws);
      }
      return;
    }

    // ---- control plane: JSON --------------------------------------------
    let msg;
    try {
      msg = JSON.parse(raw.toString('utf8'));
    } catch {
      safeSend(ws, JSON.stringify({ type: 'error', message: 'invalid_json' }));
      return;
    }

    if (msg.type === 'register_host' || msg.type === 'publish') {
      const p = touchPairing(msg.token);
      if (!p) {
        safeSend(ws, JSON.stringify({ type: 'error', message: 'unknown_or_expired_token' }));
        return;
      }
      if (ws.role === 'client') {
        safeSend(ws, JSON.stringify({ type: 'error', message: 'role_already_client' }));
        return;
      }
      ws.role = 'host';
      ws.pairingToken = msg.token;
      p.hostSockets.add(ws);

      if (msg.candidates) {
        p.candidates = sanitizeCandidates(msg.candidates);
        p.updatedAt = Date.now();
        const payload = JSON.stringify({ type: 'candidates', token: msg.token, candidates: p.candidates, updatedAt: p.updatedAt });
        for (const sub of p.subscribers) safeSend(sub, payload);
      }
      safeSend(ws, JSON.stringify({ type: 'host_registered', token: msg.token }));
      console.log(`[WS] host registered for token ${msg.token}`);
      return;
    }

    if (msg.type === 'subscribe') {
      const p = touchPairing(msg.token);
      if (!p) {
        safeSend(ws, JSON.stringify({ type: 'error', message: 'unknown_or_expired_token' }));
        return;
      }
      if (ws.role === 'host') {
        safeSend(ws, JSON.stringify({ type: 'error', message: 'role_already_host' }));
        return;
      }
      if (ws.pairingToken && pairings.has(ws.pairingToken)) {
        pairings.get(ws.pairingToken).subscribers.delete(ws);
      }
      ws.role = 'client';
      ws.pairingToken = msg.token;
      p.subscribers.add(ws);
      safeSend(ws, JSON.stringify({
        type: 'candidates',
        token: msg.token,
        candidates: p.candidates,
        updatedAt: p.updatedAt,
        hostOnline: pickHost(p) !== null,
      }));
      console.log(`[WS] client subscribed to token ${msg.token}`);

      // Notify host that client device has connected and is in standby
      for (const hws of p.hostSockets) {
        safeSend(hws, JSON.stringify({
          type: 'client_status',
          online: true,
          clientDeviceId: p.clientDeviceId,
          subscribersCount: p.subscribers.size
        }));
      }
      if (p.lastTelemetry) {
        safeSend(ws, JSON.stringify(p.lastTelemetry));
      }
      return;
    }

    if (msg.type === 'telemetry') {
      const p = touchPairing(msg.token);
      if (p) {
        p.lastTelemetry = msg;
        const out = JSON.stringify(msg);
        for (const sub of p.subscribers) safeSend(sub, out);
      }
      return;
    }

    if (msg.type === 'pipe_open') {
      console.log(`[PIPE] Client pipe_open request: token=${msg.token} streamId=${msg.streamId} role=${ws.role}`);
      const p = touchPairing(msg.token);
      if (!p || ws.role !== 'client') {
        console.warn(`[PIPE] pipe_open rejected: bad_token_or_role (has_p=${Boolean(p)}, role=${ws.role})`);
        safeSend(ws, JSON.stringify({ type: 'pipe_reject', streamId: msg.streamId, reason: 'bad_token_or_role' }));
        return;
      }
      if (p.streams.size >= MAX_STREAMS_PER_PAIRING) {
        console.warn(`[PIPE] pipe_open rejected: stream_limit`);
        safeSend(ws, JSON.stringify({ type: 'pipe_reject', streamId: msg.streamId, reason: 'stream_limit' }));
        return;
      }
      const hostWs = pickHost(p);
      if (!hostWs) {
        console.warn(`[PIPE] pipe_open rejected: no_host_online (hosts=${p.hostSockets.size})`);
        safeSend(ws, JSON.stringify({ type: 'pipe_reject', streamId: msg.streamId, reason: 'no_host_online' }));
        return;
      }
      p.streams.set(msg.streamId, { id: msg.streamId, clientWs: ws, hostWs });
      console.log(`[PIPE] pipe_open routed to host! streamId=${msg.streamId}`);
      safeSend(hostWs, JSON.stringify({ type: 'pipe_open', token: msg.token, streamId: msg.streamId }));
      return;
    }

    if (msg.type === 'pipe_ack' || msg.type === 'pipe_close') {
      const p = ws.pairingToken ? touchPairing(ws.pairingToken) : null;
      if (!p) return;
      const st = p.streams.get(msg.streamId);
      if (!st) return;
      const peer = ws === st.clientWs ? st.hostWs : ws === st.hostWs ? st.clientWs : null;
      if (peer) safeSend(peer, JSON.stringify(msg));
      if (msg.type === 'pipe_close') p.streams.delete(msg.streamId);
      return;
    }

    safeSend(ws, JSON.stringify({ type: 'error', message: 'unknown_message_type' }));
  });

  ws.on('close', () => {
    const p = ws.pairingToken ? pairings.get(ws.pairingToken) : null;
    if (!p) return;
    p.subscribers.delete(ws);
    p.hostSockets.delete(ws);
    if (ws.role === 'client') {
      for (const hws of p.hostSockets) {
        safeSend(hws, JSON.stringify({
          type: 'client_status',
          online: p.subscribers.size > 0,
          subscribersCount: p.subscribers.size
        }));
      }
    }
    if (ws.role === 'host') {
      const hostOnline = pickHost(p) !== null;
      for (const sub of p.subscribers) {
        safeSend(sub, JSON.stringify({
          type: 'host_status',
          online: hostOnline,
          reason: 'host_disconnected'
        }));
      }
    }
    for (const [sid, st] of p.streams) {
      if (st.clientWs === ws || st.hostWs === ws) {
        const peer = st.clientWs === ws ? st.hostWs : st.clientWs;
        safeSend(peer, JSON.stringify({ type: 'pipe_close', streamId: sid }));
        p.streams.delete(sid);
      }
    }
  });

  ws.on('error', () => { try { ws.terminate(); } catch {} });
});

const pingInterval = setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  });
}, 30_000);

wss.on('close', () => clearInterval(pingInterval));

setInterval(() => {
  const now = Date.now();
  for (const [room, p] of pairingsByRoom.entries()) {
    if (now > p.expiresAt) destroyPairing(p);
  }
  for (const [ip, e] of rateLimits.entries()) {
    if (now - e.windowStart > RATE_LIMIT_WINDOW_MS * 5) rateLimits.delete(ip);
  }
}, 60_000);

server.listen(PORT, HOST, () => {
  console.log(`unified P2P relay server v2.0.1 listening on ${HOST}:${PORT} (pairing TTL ${PAIRING_TTL_SECONDS}s)`);
});
