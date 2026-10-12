'use strict';

const assert = require('assert/strict');
const crypto = require('crypto');
const { once } = require('events');
const test = require('node:test');
const { PairingRateLimiter, createControlServer, createTurnCredentials } = require('../backend/pairing-service');
const { verifySessionToken } = require('../server/session-token');

const SIGNING_KEY = 'backend-test-signing-key-at-least-32-characters-000';
const CONTROL_TOKEN = 'backend-test-control-token-at-least-24-characters';
const TURN_SECRET = 'backend-test-turn-secret-at-least-32-characters-000000';

test('control backend creates a one-time pairing and issues role-bound short-lived tokens', async () => {
  const server = createControlServer({
    signingKey: SIGNING_KEY, controlApiToken: CONTROL_TOKEN,
    turnSharedSecret: TURN_SECRET, turnHost: 'turn.example.test',
    controlPublicUrl: 'https://control.example.test'
  });
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  const base = `http://127.0.0.1:${server.address().port}`;

  const create = await fetch(`${base}/v1/pairings`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ exitDeviceId: 'exitDeviceId_12345678' })
  });
  assert.equal(create.status, 201);
  const pairing = await create.json();
  assert.equal(pairing.qr.version, 2);
  assert.equal(pairing.qr.controlUrl, 'https://control.example.test');
  assert.equal(pairing.qr.room, pairing.room);
  assert.equal(pairing.qr.pairingSecret, pairing.pairingSecret);
  assert.equal(verifySessionToken(SIGNING_KEY, pairing.exitToken).role, 'exit');

  const claim = await fetch(`${base}/v1/pairings/${pairing.room}/claim`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ clientDeviceId: 'clientDeviceId_123456', pairingSecret: pairing.pairingSecret })
  });
  assert.equal(claim.status, 200);
  const client = await claim.json();
  const clientClaims = verifySessionToken(SIGNING_KEY, client.clientToken);
  assert.equal(clientClaims.role, 'client');
  assert.equal(clientClaims.room, pairing.room);

  const publishCandidate = await fetch(`${base}/v1/candidates`, {
    method: 'POST',
    headers: { authorization: `Bearer ${pairing.exitToken}`, 'content-type': 'application/json' },
    body: JSON.stringify({ candidate: { type: 'srflx', address: '203.0.113.42', port: 51820 } })
  });
  assert.equal(publishCandidate.status, 204);
  const candidates = await fetch(`${base}/v1/candidates`, {
    headers: { authorization: `Bearer ${client.clientToken}` }
  });
  assert.equal(candidates.status, 200);
  assert.deepEqual((await candidates.json()).candidates, [
    { type: 'srflx', address: '203.0.113.42', port: 51820 }
  ]);

  const turn = await fetch(`${base}/v1/turn-credentials`, {
    headers: { authorization: `Bearer ${client.clientToken}` }
  });
  assert.equal(turn.status, 200);
  const turnCredentials = await turn.json();
  assert.match(turnCredentials.username, /^\d+:clientDeviceId_123456$/);
  assert.deepEqual(turnCredentials.urls, [
    'turn:turn.example.test:3478?transport=udp',
    'turns:turn.example.test:5349?transport=tcp'
  ]);
  assert.equal(turnCredentials.credential,
    createTurnCredentials(TURN_SECRET, 'turn.example.test', clientClaims,
      Number.parseInt(turnCredentials.username.split(':', 1)[0], 10) - 600).credential);

  const replay = await fetch(`${base}/v1/pairings/${pairing.room}/claim`, {
    method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ clientDeviceId: 'anotherClientId_123456', pairingSecret: pairing.pairingSecret })
  });
  assert.equal(replay.status, 400);

  await new Promise((resolve) => server.close(resolve));
});

test('anonymous pairing creation is rate limited without putting a global server secret in the app', () => {
  const limiter = new PairingRateLimiter({ limit: 2, windowMs: 1000 });
  assert.equal(limiter.allow('192.0.2.1', 100), true);
  assert.equal(limiter.allow('192.0.2.1', 200), true);
  assert.equal(limiter.allow('192.0.2.1', 300), false);
  assert.equal(limiter.allow('192.0.2.1', 1100), true);
});
