'use strict';

const { FrameSocket, validStreamId } = require('./protocol');

const MAX_STREAMS_PER_CLIENT = 128;
const MAX_BUFFERED_OPENING_BYTES = 64 * 1024;

/**
 * A blind, authenticated relay.  It only routes encrypted envelopes between
 * a paired client and exit.  It does not open arbitrary Internet sockets.
 */
function createRelay({ server, verifyToken, logger = console, connectionEvent = 'connection' }) {
  const rooms = new Map();

  function roomFor(roomId) {
    let room = rooms.get(roomId);
    if (!room) {
      room = { exit: null, clients: new Set(), streams: new Map() };
      rooms.set(roomId, room);
    }
    return room;
  }

  function reject(peer, code) {
    peer.frame.send({ type: 'error', code });
  }

  function route(peer, message) {
    const { room } = peer;
    if (!validStreamId(message.streamId)) return reject(peer, 'invalid_stream_id');
    let stream = room.streams.get(message.streamId);

    if (message.type === 'open') {
      if (peer.role !== 'client') return reject(peer, 'only_client_opens');
      if (stream) return reject(peer, 'stream_exists');
      const ownedStreams = [...room.streams.values()].filter((item) => item.client === peer).length;
      if (ownedStreams >= MAX_STREAMS_PER_CLIENT) return reject(peer, 'stream_limit');
      if (!room.exit) return reject(peer, 'exit_unavailable');
      stream = { client: peer, exit: room.exit, phase: 'opening', queued: [], queuedBytes: 0 };
      room.streams.set(message.streamId, stream);
      stream.exit.frame.send(message);
      return;
    }

    if (!stream) return reject(peer, 'unknown_stream');
    const fromClient = peer === stream.client;
    const fromExit = peer === stream.exit;
    if (!fromClient && !fromExit) return reject(peer, 'not_stream_owner');

    if (message.type === 'ready') {
      if (!fromExit || stream.phase !== 'opening') return reject(peer, 'unexpected_ready');
      stream.phase = 'ready';
      stream.client.frame.send(message);
      for (const queued of stream.queued) stream.exit.frame.send(queued);
      stream.queued = [];
      stream.queuedBytes = 0;
      return;
    }

    if (message.type === 'data') {
      if (typeof message.payload !== 'string' || message.payload.length > 1_400_000) {
        return reject(peer, 'invalid_payload');
      }
      if (stream.phase === 'opening' && fromClient) {
        const bytes = Buffer.byteLength(message.payload, 'utf8');
        if (stream.queuedBytes + bytes > MAX_BUFFERED_OPENING_BYTES) {
          stream.client.frame.send({ type: 'error', streamId: message.streamId, code: 'opening_buffer_full' });
          return closeStream(room, message.streamId, 'opening_buffer_full');
        }
        stream.queued.push(message);
        stream.queuedBytes += bytes;
        return;
      }
      if (stream.phase !== 'ready') return reject(peer, 'stream_not_ready');
      (fromClient ? stream.exit : stream.client).frame.send(message);
      return;
    }

    if (message.type === 'close' || message.type === 'reject') {
      const other = fromClient ? stream.exit : stream.client;
      other.frame.send({ type: message.type, streamId: message.streamId, code: message.code });
      return closeStream(room, message.streamId, message.code || 'closed');
    }
    reject(peer, 'unsupported_frame');
  }

  function closeStream(room, streamId, code) {
    const stream = room.streams.get(streamId);
    if (!stream) return;
    room.streams.delete(streamId);
    if (!stream.client.frame.closed) stream.client.frame.send({ type: 'close', streamId, code });
    if (!stream.exit.frame.closed) stream.exit.frame.send({ type: 'close', streamId, code });
  }

  function removePeer(peer) {
    if (!peer.room) return;
    const room = peer.room;
    if (peer.role === 'exit' && room.exit === peer) room.exit = null;
    room.clients.delete(peer);
    for (const [streamId, stream] of room.streams) {
      if (stream.client === peer || stream.exit === peer) closeStream(room, streamId, 'peer_disconnected');
    }
    if (!room.exit && room.clients.size === 0 && room.streams.size === 0) rooms.delete(peer.roomId);
  }

  server.on(connectionEvent, (socket) => {
    const frame = new FrameSocket(socket);
    const peer = { frame, room: null, roomId: null, role: null, deviceId: null };
    const authenticationTimeout = setTimeout(() => {
      if (!peer.room) socket.destroy(new Error('authentication timeout'));
    }, 10_000).unref();

    frame.on('message', (message) => {
      if (!peer.room) {
        if (message.type !== 'auth') return reject(peer, 'authenticate_first');
        try {
          const claims = verifyToken(message.token);
          if (claims.room !== message.room || claims.role !== message.role || claims.deviceId !== message.deviceId) {
            throw new Error('claims mismatch');
          }
          peer.roomId = claims.room;
          peer.role = claims.role;
          peer.deviceId = claims.deviceId;
          peer.room = roomFor(claims.room);
          if (peer.role === 'exit') {
            if (peer.room.exit && peer.room.exit !== peer) peer.room.exit.frame.end();
            peer.room.exit = peer;
          } else {
            peer.room.clients.add(peer);
          }
          clearTimeout(authenticationTimeout);
          frame.send({ type: 'authenticated', room: peer.roomId, role: peer.role });
        } catch (error) {
          logger.warn?.(`relay authentication denied: ${error.message}`);
          reject(peer, 'authentication_failed');
          frame.end();
        }
        return;
      }
      route(peer, message);
    });
    frame.on('close', () => {
      clearTimeout(authenticationTimeout);
      removePeer(peer);
    });
  });

  return {
    rooms,
    close(callback) { server.close(callback); }
  };
}

module.exports = { createRelay, MAX_BUFFERED_OPENING_BYTES };
