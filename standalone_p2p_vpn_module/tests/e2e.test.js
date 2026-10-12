'use strict';

const assert = require('assert/strict');
const { execFileSync } = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const net = require('net');
const os = require('os');
const path = require('path');
const test = require('node:test');
const tls = require('tls');
const { once } = require('events');

const { createRelay } = require('../server/relay');
const { mintSessionToken, verifySessionToken } = require('../server/session-token');
const { FrameSocket } = require('../server/protocol');
const { TunnelPeer } = require('../frontend/reference-client/secure-peer');
const { ExitGateway } = require('../frontend/reference-client/exit-gateway');

const SIGNING_KEY = 'test-only-signing-key-with-at-least-32-characters-000';
const PAIRING_SECRET = 'test-only-pairing-secret-32-bytes-long-000000';

function deviceId(label) { return `${label}DeviceId_12345678`; }
function token(room, role, label) {
  return mintSessionToken(SIGNING_KEY, { room, role, deviceId: deviceId(label) }, 120);
}

function createCertificate() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'p2p-relay-cert-'));
  const key = path.join(dir, 'key.pem');
  const cert = path.join(dir, 'cert.pem');
  execFileSync('openssl', [
    'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-sha256', '-days', '1',
    '-subj', '/CN=localhost', '-keyout', key, '-out', cert
  ], { stdio: 'ignore' });
  return { dir, key, cert };
}

async function listen(server) {
  server.listen(0, '127.0.0.1');
  await once(server, 'listening');
  return server.address().port;
}

async function close(server) {
  if (!server.listening) return;
  server.closeAllConnections?.();
  await new Promise((resolve) => server.close(resolve));
}

async function peerFor(port, room, role, label, suppliedToken = token(room, role, label)) {
  const socket = tls.connect({ host: '127.0.0.1', port, minVersion: 'TLSv1.3', rejectUnauthorized: false });
  socket.on('error', () => {});
  await once(socket, 'secureConnect');
  const peer = new TunnelPeer({
    socket, room, role, deviceId: deviceId(label), token: suppliedToken, pairingSecret: PAIRING_SECRET
  });
  return peer;
}

function disposePeer(peer) {
  peer.frame.socket.destroy();
}

test('TLS relay forwards only opaque E2E data and preserves data written before exit readiness', { timeout: 10_000 }, async (t) => {
  const certificate = createCertificate();
  const relayServer = tls.createServer({
    minVersion: 'TLSv1.3', key: fs.readFileSync(certificate.key), cert: fs.readFileSync(certificate.cert)
  });
  createRelay({
    server: relayServer,
    connectionEvent: 'secureConnection',
    verifyToken: (value) => verifySessionToken(SIGNING_KEY, value),
    logger: { warn() {} }
  });
  const relayPort = await listen(relayServer);
  const echoServer = net.createServer((socket) => socket.pipe(socket));
  const echoPort = await listen(echoServer);
  const room = crypto.randomBytes(18).toString('base64url');
  const exit = await peerFor(relayPort, room, 'exit', 'exit');
  const client = await peerFor(relayPort, room, 'client', 'client');
  const gateway = new ExitGateway(exit, { allowPrivateForTests: true });
  await Promise.all([exit.ready, client.ready]);

  const stream = client.open({ host: '127.0.0.1', port: echoPort });
  const reply = once(stream, 'data');
  // This emulates the SOCKS greeting arriving immediately after pipe_open.
  stream.write(Buffer.from('SOCKS-first-bytes'));
  const [data] = await reply;
  assert.equal(data.toString(), 'SOCKS-first-bytes');
  assert.equal(stream.ready, true);

  stream.close();
  gateway.closeAll();
  disposePeer(client);
  disposePeer(exit);
  await close(echoServer);
  await close(relayServer);
  fs.rmSync(certificate.dir, { recursive: true, force: true });
});

test('relay rejects forged credentials and client gets no route without an exit', { timeout: 10_000 }, async (t) => {
  const certificate = createCertificate();
  const relayServer = tls.createServer({
    minVersion: 'TLSv1.3', key: fs.readFileSync(certificate.key), cert: fs.readFileSync(certificate.cert)
  });
  createRelay({
    server: relayServer,
    connectionEvent: 'secureConnection',
    verifyToken: (value) => verifySessionToken(SIGNING_KEY, value),
    logger: { warn() {} }
  });
  const relayPort = await listen(relayServer);
  const room = crypto.randomBytes(18).toString('base64url');

  const badSocket = tls.connect({ host: '127.0.0.1', port: relayPort, minVersion: 'TLSv1.3', rejectUnauthorized: false });
  badSocket.on('error', () => {});
  await once(badSocket, 'secureConnect');
  const badFrame = new FrameSocket(badSocket);
  const rejected = once(badFrame, 'message');
  badFrame.send({ type: 'auth', room, role: 'client', deviceId: deviceId('bad'), token: 'forged.token' });
  const [rejection] = await rejected;
  assert.deepEqual(rejection, { type: 'error', code: 'authentication_failed' });
  badSocket.destroy();

  const client = await peerFor(relayPort, room, 'client', 'client');
  await client.ready;
  const unavailable = once(client, 'relayError');
  client.open({ host: 'example.com', port: 443 });
  const [error] = await unavailable;
  assert.equal(error.code, 'exit_unavailable');
  disposePeer(client);
  await close(relayServer);
  fs.rmSync(certificate.dir, { recursive: true, force: true });
});

test('exit default policy denies a loopback/private destination', { timeout: 10_000 }, async (t) => {
  const certificate = createCertificate();
  const relayServer = tls.createServer({
    minVersion: 'TLSv1.3', key: fs.readFileSync(certificate.key), cert: fs.readFileSync(certificate.cert)
  });
  createRelay({
    server: relayServer,
    connectionEvent: 'secureConnection',
    verifyToken: (value) => verifySessionToken(SIGNING_KEY, value),
    logger: { warn() {} }
  });
  const relayPort = await listen(relayServer);
  const room = crypto.randomBytes(18).toString('base64url');
  const exit = await peerFor(relayPort, room, 'exit', 'exit');
  const client = await peerFor(relayPort, room, 'client', 'client');
  new ExitGateway(exit);
  await Promise.all([exit.ready, client.ready]);

  const denied = once(client, 'reject');
  client.open({ host: '127.0.0.1', port: 9 });
  const [message] = await denied;
  assert.equal(message.code, 'private_target_denied');

  disposePeer(client);
  disposePeer(exit);
  await close(relayServer);
  fs.rmSync(certificate.dir, { recursive: true, force: true });
});
