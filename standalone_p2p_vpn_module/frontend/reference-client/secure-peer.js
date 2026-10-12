'use strict';

// Node reference endpoint for protocol testing. Android must use the matching
// AES-GCM construction in frontend/android/TunnelCipher.java.
const crypto = require('crypto');
const { EventEmitter } = require('events');
const { FrameSocket } = require('../../server/protocol');

function asBuffer(value) { return Buffer.isBuffer(value) ? value : Buffer.from(value); }

function deriveTunnelKey(pairingSecret, room) {
  return Buffer.from(crypto.hkdfSync(
    'sha256', asBuffer(pairingSecret), Buffer.from(room, 'utf8'),
    Buffer.from('KotSafe P2P tunnel v1 end-to-end key', 'utf8'), 32
  ));
}

function nonceFor(key, streamId, direction, sequence) {
  const sequenceBytes = Buffer.alloc(8);
  sequenceBytes.writeBigUInt64BE(BigInt(sequence));
  return crypto.createHmac('sha256', key)
    .update(streamId).update('\0').update(direction).update('\0').update(sequenceBytes)
    .digest().subarray(0, 12);
}

function aad(room, streamId, direction, sequence) {
  return Buffer.from(`${room}\0${streamId}\0${direction}\0${sequence}`, 'utf8');
}

class TunnelCipher {
  constructor(pairingSecret, room) {
    this.key = deriveTunnelKey(pairingSecret, room);
    this.room = room;
    this.sent = new Map();
    this.received = new Map();
  }

  seal(streamId, direction, plaintext) {
    const id = `${streamId}:${direction}`;
    const sequence = this.sent.get(id) || 0;
    this.sent.set(id, sequence + 1);
    const cipher = crypto.createCipheriv('aes-256-gcm', this.key, nonceFor(this.key, streamId, direction, sequence));
    cipher.setAAD(aad(this.room, streamId, direction, sequence));
    const ciphertext = Buffer.concat([cipher.update(asBuffer(plaintext)), cipher.final()]);
    const packet = Buffer.allocUnsafe(8 + ciphertext.length + 16);
    packet.writeBigUInt64BE(BigInt(sequence), 0);
    ciphertext.copy(packet, 8);
    cipher.getAuthTag().copy(packet, 8 + ciphertext.length);
    return packet.toString('base64url');
  }

  open(streamId, direction, encoded) {
    const packet = Buffer.from(encoded, 'base64url');
    if (packet.length < 24) throw new Error('ciphertext is too short');
    const sequence = packet.readBigUInt64BE(0);
    const id = `${streamId}:${direction}`;
    const expected = this.received.get(id) || 0n;
    if (sequence !== expected) throw new Error('replayed or out-of-order packet');
    const tag = packet.subarray(packet.length - 16);
    const ciphertext = packet.subarray(8, packet.length - 16);
    const decipher = crypto.createDecipheriv('aes-256-gcm', this.key, nonceFor(this.key, streamId, direction, sequence));
    decipher.setAAD(aad(this.room, streamId, direction, sequence));
    decipher.setAuthTag(tag);
    const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
    this.received.set(id, sequence + 1n);
    return plaintext;
  }
}

class BufferedTunnelStream extends EventEmitter {
  constructor(peer, target) {
    super();
    this.peer = peer;
    this.target = target;
    this.streamId = crypto.randomBytes(18).toString('base64url');
    this.buffer = [];
    this.bufferBytes = 0;
    this.ready = false;
    this.closed = false;
    this.maxBufferBytes = 64 * 1024;
  }

  begin() {
    const payload = this.peer.cipher.seal(this.streamId, 'client-to-exit', JSON.stringify(this.target));
    this.peer.frame.send({ type: 'open', streamId: this.streamId, payload });
  }

  write(chunk) {
    if (this.closed) throw new Error('stream is closed');
    const data = asBuffer(chunk);
    if (!this.ready) {
      if (this.bufferBytes + data.length > this.maxBufferBytes) throw new Error('pre-ready buffer is full');
      this.buffer.push(data);
      this.bufferBytes += data.length;
      return;
    }
    this.peer._sendData(this.streamId, 'client-to-exit', data);
  }

  _ready() {
    if (this.ready || this.closed) return;
    this.ready = true;
    for (const chunk of this.buffer) this.peer._sendData(this.streamId, 'client-to-exit', chunk);
    this.buffer = [];
    this.bufferBytes = 0;
    this.emit('ready');
  }

  _data(chunk) { if (!this.closed) this.emit('data', chunk); }

  close(code = 'closed') {
    if (this.closed) return;
    this.closed = true;
    this.peer.frame.send({ type: 'close', streamId: this.streamId, code });
    this.emit('close', code);
  }
}

class TunnelPeer extends EventEmitter {
  constructor({ socket, room, role, deviceId, token, pairingSecret }) {
    super();
    this.room = room;
    this.role = role;
    this.deviceId = deviceId;
    this.token = token;
    this.cipher = new TunnelCipher(pairingSecret, room);
    this.frame = new FrameSocket(socket);
    this.streams = new Map();
    this.ready = new Promise((resolve, reject) => { this._resolveReady = resolve; this._rejectReady = reject; });
    this.frame.on('message', (message) => this._onFrame(message));
    this.frame.on('socketError', (error) => this._rejectReady(error));
    this.frame.on('close', () => this.emit('disconnect'));
    this.frame.send({ type: 'auth', room, role, deviceId, token });
  }

  open(target) {
    if (this.role !== 'client') throw new Error('only a client can open streams');
    const stream = new BufferedTunnelStream(this, target);
    this.streams.set(stream.streamId, stream);
    stream.begin();
    return stream;
  }

  accept(streamId) {
    this.frame.send({ type: 'ready', streamId });
  }

  reject(streamId, code) {
    this.frame.send({ type: 'reject', streamId, code });
  }

  _sendData(streamId, direction, data) {
    const payload = this.cipher.seal(streamId, direction, data);
    this.frame.send({ type: 'data', streamId, payload });
  }

  _onFrame(message) {
    if (message.type === 'authenticated') return this._resolveReady();
    if (message.type === 'error') return this.emit('relayError', message);
    if (message.type === 'open' && this.role === 'exit') {
      try {
        const target = JSON.parse(this.cipher.open(message.streamId, 'client-to-exit', message.payload).toString('utf8'));
        this.emit('open', { streamId: message.streamId, target });
      } catch (error) {
        this.reject(message.streamId, 'invalid_open_ciphertext');
      }
      return;
    }
    if (message.type === 'ready' && this.role === 'client') {
      const stream = this.streams.get(message.streamId);
      if (stream) stream._ready();
      return;
    }
    if (message.type === 'data') {
      const direction = this.role === 'client' ? 'exit-to-client' : 'client-to-exit';
      try {
        const data = this.cipher.open(message.streamId, direction, message.payload);
        const stream = this.streams.get(message.streamId);
        if (stream) stream._data(data);
        this.emit('data', { streamId: message.streamId, data });
      } catch {
        this.reject(message.streamId, 'invalid_data_ciphertext');
      }
      return;
    }
    if (message.type === 'close' || message.type === 'reject') {
      const stream = this.streams.get(message.streamId);
      if (stream) {
        stream.closed = true;
        stream.emit('close', message.code || message.type);
        this.streams.delete(message.streamId);
      }
      this.emit(message.type, message);
    }
  }
}

module.exports = { TunnelCipher, TunnelPeer };
