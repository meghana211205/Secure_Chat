'use strict';
/**
 * Wire framing: every message is a length-prefixed JSON frame.
 *   [ 4 bytes big-endian length N ][ N bytes UTF-8 JSON ]
 * TCP is a byte stream with no message boundaries, so the length prefix tells the
 * receiver exactly where each frame ends.
 *
 * A FrameParser buffers incoming bytes and emits whole frames as they complete.
 */
const LEN = 4;
const MAX_FRAME = 1 << 20; // 1 MiB cap

function encode(obj) {
  const payload = Buffer.from(JSON.stringify(obj), 'utf8');
  if (payload.length > MAX_FRAME) throw new Error('frame too large');
  const head = Buffer.alloc(LEN);
  head.writeUInt32BE(payload.length, 0);
  return Buffer.concat([head, payload]);
}

/** Accumulates bytes from a socket and yields complete frames. */
class FrameParser {
  constructor() { this.buf = Buffer.alloc(0); }

  /** Push received bytes; returns an array of decoded frame objects now available. */
  push(chunk) {
    this.buf = Buffer.concat([this.buf, chunk]);
    const frames = [];
    while (this.buf.length >= LEN) {
      const n = this.buf.readUInt32BE(0);
      if (n > MAX_FRAME) throw new Error('frame too large');
      if (this.buf.length < LEN + n) break;         // wait for the rest
      const payload = this.buf.slice(LEN, LEN + n);
      this.buf = this.buf.slice(LEN + n);
      frames.push(JSON.parse(payload.toString('utf8')));
    }
    return frames;
  }
}

function writeFrame(socket, obj) { socket.write(encode(obj)); }

module.exports = { encode, FrameParser, writeFrame, MAX_FRAME };
