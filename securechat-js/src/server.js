'use strict';
/**
 * Relay server: a deliberately "zero-knowledge" router.
 *   - stores each user's PUBLIC prekey bundle so others can start sessions
 *   - forwards encrypted messages by reading only `to` / `from`
 *   - never holds any private key, shared secret, or plaintext
 * If seized or malicious, it would still see only ciphertext.
 */
const net = require('net');
const { FrameParser, writeFrame } = require('./protocol');

class RelayServer {
  constructor(host = '127.0.0.1', port = 9999, log = console) {
    this.host = host; this.port = port; this.log = log;
    this.bundles = new Map();   // user -> public bundle
    this.online = new Map();    // user -> socket
    this.server = null;
  }

  _handle(socket) {
    const parser = new FrameParser();
    let user = null;
    socket.on('data', (chunk) => {
      let frames;
      try { frames = parser.push(chunk); } catch { socket.destroy(); return; }
      for (const frame of frames) {
        switch (frame.type) {
          case 'register':
            user = frame.user;
            this.bundles.set(user, frame.bundle);
            this.online.set(user, socket);
            this.log.info?.(`registered ${user}`);
            writeFrame(socket, { type: 'info', text: `registered as ${user}` });
            break;
          case 'bundle_req':
            writeFrame(socket, { type: 'bundle', user: frame.user,
              bundle: this.bundles.get(frame.user) || null });
            break;
          case 'message': {
            const dest = this.online.get(frame.to);
            this.log.info?.(`relay ${frame.from} -> ${frame.to} ` +
              `(${(frame.body || '').length / 2} bytes ciphertext, cannot read)`);
            if (dest) writeFrame(dest, frame);
            else writeFrame(socket, { type: 'error', text: `${frame.to} is offline` });
            break;
          }
          default:
            writeFrame(socket, { type: 'error', text: 'unknown frame' });
        }
      }
    });
    const cleanup = () => {
      if (user && this.online.get(user) === socket) {
        this.online.delete(user);
        this.log.info?.(`${user} disconnected`);
      }
    };
    socket.on('close', cleanup);
    socket.on('error', cleanup);
  }

  listen() {
    return new Promise((resolve) => {
      this.server = net.createServer((s) => this._handle(s));
      this.server.listen(this.port, this.host, () => {
        this.port = this.server.address().port;
        this.log.info?.(`relay listening on ${this.host}:${this.port}`);
        resolve(this.port);
      });
    });
  }

  close() { return new Promise((r) => (this.server ? this.server.close(r) : r())); }
}

if (require.main === module) {
  const args = process.argv.slice(2);
  const port = args.includes('--port') ? Number(args[args.indexOf('--port') + 1]) : 9999;
  const host = args.includes('--host') ? args[args.indexOf('--host') + 1] : '127.0.0.1';
  new RelayServer(host, port).listen();
  process.on('SIGINT', () => { console.log('\nserver stopped'); process.exit(0); });
}

module.exports = { RelayServer };
