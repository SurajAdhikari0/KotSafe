'use strict';

// One JSON message is carried in each length-prefixed frame.  All traffic
// payloads are opaque base64url ciphertext.  The relay only reads routing
// fields (room, streamId and frame type); it never receives a tunnel key.
const { EventEmitter } = require('events');

const MAX_FRAME_BYTES = 1024 * 1024;

function encodeFrame(message) {
  const body = Buffer.from(JSON.stringify(message), 'utf8');
  if (body.length === 0 || body.length > MAX_FRAME_BYTES) {
    throw new Error('frame size is outside permitted bounds');
  }
  const header = Buffer.allocUnsafe(4);
  header.writeUInt32BE(body.length, 0);
  return Buffer.concat([header, body]);
}

class FrameSocket extends EventEmitter {
  constructor(socket) {
    super();
    this.socket = socket;
    this.pending = Buffer.alloc(0);
    this.closed = false;
    socket.on('data', (chunk) => this._onData(chunk));
    socket.on('error', (error) => this.emit('socketError', error));
    socket.on('close', () => {
      this.closed = true;
      this.emit('close');
    });
  }

  send(message) {
    if (!this.closed && !this.socket.destroyed) this.socket.write(encodeFrame(message));
  }

  end() {
    if (!this.socket.destroyed) this.socket.end();
  }

  _onData(chunk) {
    this.pending = Buffer.concat([this.pending, chunk]);
    while (this.pending.length >= 4) {
      const length = this.pending.readUInt32BE(0);
      if (length === 0 || length > MAX_FRAME_BYTES) {
        this.socket.destroy(new Error('invalid frame length'));
        return;
      }
      if (this.pending.length < length + 4) return;
      const raw = this.pending.subarray(4, length + 4);
      this.pending = this.pending.subarray(length + 4);
      try {
        const message = JSON.parse(raw.toString('utf8'));
        if (!message || typeof message !== 'object' || Array.isArray(message)) {
          throw new Error('frame must be a JSON object');
        }
        this.emit('message', message);
      } catch (error) {
        this.socket.destroy(error);
        return;
      }
    }
  }
}

function validStreamId(value) {
  return typeof value === 'string' && /^[A-Za-z0-9_-]{12,96}$/.test(value);
}

module.exports = { FrameSocket, MAX_FRAME_BYTES, encodeFrame, validStreamId };
