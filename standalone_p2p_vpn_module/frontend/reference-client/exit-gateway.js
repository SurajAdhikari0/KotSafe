'use strict';

const dns = require('dns');
const net = require('net');

function isPrivateOrLocal(address) {
  const normalized = address.toLowerCase();
  if (normalized.includes(':')) {
    if (normalized.startsWith('::ffff:')) return isPrivateOrLocal(normalized.slice(7));
    return normalized === '::' || normalized === '::1' || normalized.startsWith('fc') ||
      normalized.startsWith('fd') || normalized.startsWith('fe80:') || normalized.startsWith('ff');
  }
  const parts = normalized.split('.').map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) return true;
  const [a, b] = parts;
  return a === 0 || a === 10 || a === 127 || a >= 224 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && (b === 0 || b === 168)) ||
    (a === 198 && (b === 18 || b === 19));
}

/**
 * Reference exit gateway. Android production code should open each allowed
 * destination with VpnService.protect(fd), enforcing an equivalent policy.
 */
class ExitGateway {
  constructor(peer, { allowPrivateForTests = false, allowHost = null } = {}) {
    this.peer = peer;
    this.allowPrivateForTests = allowPrivateForTests;
    this.allowHost = allowHost || (() => true);
    this.sockets = new Map();
    peer.on('open', ({ streamId, target }) => this._open(streamId, target));
    peer.on('data', ({ streamId, data }) => this.sockets.get(streamId)?.write(data));
    peer.on('close', ({ streamId }) => this._close(streamId));
    peer.on('reject', ({ streamId }) => this._close(streamId));
  }

  _open(streamId, target) {
    if (!target || typeof target.host !== 'string' || !Number.isInteger(target.port) || target.port < 1 || target.port > 65535) {
      return this.peer.reject(streamId, 'invalid_target');
    }
    if (!this.allowHost(target.host, target.port)) return this.peer.reject(streamId, 'target_denied');
    // Resolve first and connect to the resolved address: checking the hostname
    // alone allows DNS rebinding to a private Android/LAN endpoint.
    dns.lookup(target.host, { all: false }, (error, address) => {
      if (error) return this.peer.reject(streamId, 'dns_lookup_failed');
      if (!this.allowPrivateForTests && isPrivateOrLocal(address)) return this.peer.reject(streamId, 'private_target_denied');
      const socket = net.createConnection({ host: address, port: target.port });
      this.sockets.set(streamId, socket);
      socket.once('connect', () => this.peer.accept(streamId));
      socket.on('data', (data) => this.peer._sendData(streamId, 'exit-to-client', data));
      socket.on('error', () => this.peer.reject(streamId, 'outbound_connect_failed'));
      socket.on('close', () => {
        this.sockets.delete(streamId);
        this.peer.frame.send({ type: 'close', streamId, code: 'outbound_closed' });
      });
    });
  }

  _close(streamId) {
    const socket = this.sockets.get(streamId);
    if (socket) socket.destroy();
    this.sockets.delete(streamId);
  }

  closeAll() {
    for (const socket of this.sockets.values()) socket.destroy();
    this.sockets.clear();
  }
}

module.exports = { ExitGateway, isPrivateOrLocal };
