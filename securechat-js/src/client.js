'use strict';
/**
 * Async client. All cryptography happens here, on the user's machine.
 * A single socket data handler dispatches frames; request/reply calls (fetching a
 * prekey bundle) wait on a promise the handler resolves, so nothing competes to read.
 */
const net = require('net');
const { FrameParser, writeFrame } = require('./protocol');
const {
  Identity, x3dhInitiator, x3dhResponder, Header, DoubleRatchet,
} = require('./ratchet');

class SecureChatClient {
  constructor(username, host = '127.0.0.1', port = 9999) {
    this.username = username; this.host = host; this.port = port;
    this.identity = new Identity();
    this.sessions = new Map();          // peer -> DoubleRatchet
    this.socket = null;
    this.parser = new FrameParser();
    this.onMessage = null;              // (sender, text) => {}
    this._bundleWaiters = new Map();    // peer -> resolve fn
    this._pendingHandshake = new Map(); // peer -> X3DH material to attach once
  }

  connect() {
    return new Promise((resolve, reject) => {
      this.socket = net.createConnection(this.port, this.host, () => {
        writeFrame(this.socket, { type: 'register', user: this.username,
          bundle: this.identity.bundle() });
        resolve();
      });
      this.socket.on('data', (chunk) => {
        let frames;
        try { frames = this.parser.push(chunk); } catch { return; }
        for (const frame of frames) this._dispatch(frame);
      });
      this.socket.on('error', reject);
    });
  }

  _dispatch(frame) {
    if (frame.type === 'message') {
      this._handleMessage(frame);
    } else if (frame.type === 'bundle') {
      const w = this._bundleWaiters.get(frame.user);
      if (w) { this._bundleWaiters.delete(frame.user); w(frame.bundle); }
    } else if (frame.type === 'error' && this.onMessage) {
      this.onMessage('server', '[error] ' + frame.text);
    }
  }

  _fetchBundle(peer) {
    return new Promise((resolve, reject) => {
      this._bundleWaiters.set(peer, resolve);
      writeFrame(this.socket, { type: 'bundle_req', user: peer });
      setTimeout(() => {
        if (this._bundleWaiters.has(peer)) {
          this._bundleWaiters.delete(peer);
          reject(new Error(`no prekey bundle for ${peer}`));
        }
      }, 5000);
    });
  }

  async send(peer, text) {
    if (!this.sessions.has(peer)) {               // first message: initiator
      const bundle = await this._fetchBundle(peer);
      if (!bundle) throw new Error(`${peer} is not registered`);
      const { shared, identityPub, ephemeralPub } = x3dhInitiator(this.identity, bundle);
      this.sessions.set(peer, DoubleRatchet.initInitiator(
        shared, Buffer.from(bundle.signedPrekey, 'hex')));
      this._pendingHandshake.set(peer,
        { id: identityPub.toString('hex'), eph: ephemeralPub.toString('hex') });
    }
    const { header, blob } = this.sessions.get(peer).encrypt(Buffer.from(text, 'utf8'));
    const frame = { type: 'message', to: peer, from: this.username,
      header: header.toBytes().toString('hex'), body: blob.toString('hex') };
    if (this._pendingHandshake.has(peer)) {
      frame.x3dh = this._pendingHandshake.get(peer);
      this._pendingHandshake.delete(peer);
    }
    writeFrame(this.socket, frame);
  }

  _handleMessage(frame) {
    const peer = frame.from;
    if (!this.sessions.has(peer)) {               // first message: responder
      const x = frame.x3dh;
      const shared = x3dhResponder(this.identity,
        Buffer.from(x.id, 'hex'), Buffer.from(x.eph, 'hex'));
      this.sessions.set(peer, DoubleRatchet.initResponder(shared, this.identity.signedPrekey));
    }
    const header = Header.fromBytes(Buffer.from(frame.header, 'hex'));
    const plaintext = this.sessions.get(peer).decrypt(header, Buffer.from(frame.body, 'hex'));
    if (this.onMessage) this.onMessage(peer, plaintext.toString('utf8'));
  }

  close() { if (this.socket) this.socket.end(); }
}

module.exports = { SecureChatClient };
