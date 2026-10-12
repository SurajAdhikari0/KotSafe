'use strict';

const fs = require('fs');
const tls = require('tls');
const { createRelay } = require('./relay');
const { verifySessionToken } = require('./session-token');

const port = Number.parseInt(process.env.RELAY_PORT || '9443', 10);
const signingKey = process.env.RELAY_SIGNING_KEY;
const keyPath = process.env.TLS_KEY_PATH;
const certPath = process.env.TLS_CERT_PATH;

if (!signingKey || !keyPath || !certPath) {
  throw new Error('Set RELAY_SIGNING_KEY, TLS_KEY_PATH and TLS_CERT_PATH. Plain TCP is deliberately unsupported.');
}

const server = tls.createServer({
  minVersion: 'TLSv1.3',
  key: fs.readFileSync(keyPath),
  cert: fs.readFileSync(certPath)
});

createRelay({
  server,
  verifyToken: (token) => verifySessionToken(signingKey, token),
  connectionEvent: 'secureConnection'
});

server.listen(port, '0.0.0.0', () => console.log(`blind P2P relay listening on ${port}/TLS`));
