'use strict';
/**
 * X3DH-style handshake + Double Ratchet.
 *
 * WHY: a single key for a whole conversation is fragile; if it leaks, every message is
 * exposed. The Double Ratchet gives:
 *   - Forward secrecy: a key compromised today cannot decrypt yesterday's messages.
 *   - Post-compromise security: after state theft, the next DH ratchet step mixes in
 *     fresh randomness the attacker never saw, restoring secrecy for future messages.
 *
 * TWO RATCHETS:
 *   1. Symmetric ratchet - a one-way KDF advances a chain for every message, so each
 *      message key is unique and cannot be worked backwards.
 *   2. DH ratchet - when the conversation turns, a new DH key pair is mixed into the
 *      root key, reseeding the chains.
 *
 * Faithful, readable port of Signal's Double Ratchet using X25519 / HKDF / AES-256-GCM.
 */
const { DHKeyPair, dh, hkdf, kdfRk, kdfCk, KEY_LEN } = require('./crypto');
const crypto = require('crypto');

const MAX_SKIP = 1000;  // tolerated out-of-order / dropped messages

// --------------------------------------------------------------- X3DH
/** A party's long-term identity plus the prekeys it offers to others. */
class Identity {
  constructor() {
    this.identity = new DHKeyPair();
    this.signedPrekey = new DHKeyPair();
    this.oneTimePrekey = new DHKeyPair();
  }
  bundle() {
    return {
      identityKey: this.identity.publicBytes.toString('hex'),
      signedPrekey: this.signedPrekey.publicBytes.toString('hex'),
      oneTimePrekey: this.oneTimePrekey.publicBytes.toString('hex'),
    };
  }
}

function bundleToBytes(b) {
  return {
    identityKey: Buffer.from(b.identityKey, 'hex'),
    signedPrekey: Buffer.from(b.signedPrekey, 'hex'),
    oneTimePrekey: Buffer.from(b.oneTimePrekey, 'hex'),
  };
}

/** Initiator side. Returns {shared, identityPub, ephemeralPub}. */
function x3dhInitiator(me, theirBundle) {
  const their = bundleToBytes(theirBundle);
  const ephemeral = new DHKeyPair();
  const dh1 = dh(me.identity, their.signedPrekey);
  const dh2 = dh(ephemeral, their.identityKey);
  const dh3 = dh(ephemeral, their.signedPrekey);
  const dh4 = dh(ephemeral, their.oneTimePrekey);
  const shared = hkdf(Buffer.concat([dh1, dh2, dh3, dh4]), KEY_LEN, 'SecureChat-X3DH');
  return { shared, identityPub: me.identity.publicBytes, ephemeralPub: ephemeral.publicBytes };
}

/** Responder side: recompute the same shared secret. */
function x3dhResponder(me, initiatorIdentity, initiatorEphemeral) {
  const dh1 = dh(me.signedPrekey, initiatorIdentity);
  const dh2 = dh(me.identity, initiatorEphemeral);
  const dh3 = dh(me.signedPrekey, initiatorEphemeral);
  const dh4 = dh(me.oneTimePrekey, initiatorEphemeral);
  return hkdf(Buffer.concat([dh1, dh2, dh3, dh4]), KEY_LEN, 'SecureChat-X3DH');
}

// ------------------------------------------------------- Double Ratchet
/** Header sent in the clear with each message (authenticated as associated data). */
class Header {
  constructor(dhPub, pn, n) { this.dh = dhPub; this.pn = pn; this.n = n; }
  toBytes() {
    return Buffer.from(JSON.stringify({ dh: this.dh.toString('hex'), pn: this.pn, n: this.n }));
  }
  static fromBytes(raw) {
    const d = JSON.parse(raw.toString());
    return new Header(Buffer.from(d.dh, 'hex'), d.pn, d.n);
  }
}

class DoubleRatchet {
  constructor(state) { this.s = state; }

  static initInitiator(shared, remoteSignedPrekey) {
    const dhSelf = new DHKeyPair();
    const { rootKey, chainKey } = kdfRk(shared, dh(dhSelf, remoteSignedPrekey));
    return new DoubleRatchet({
      dhSelf, dhRemote: Buffer.from(remoteSignedPrekey), rootKey,
      chainSend: chainKey, chainRecv: null,
      nSend: 0, nRecv: 0, pn: 0, skipped: new Map(),
    });
  }

  static initResponder(shared, signedPrekeyPair) {
    return new DoubleRatchet({
      dhSelf: signedPrekeyPair, dhRemote: null, rootKey: shared,
      chainSend: null, chainRecv: null,
      nSend: 0, nRecv: 0, pn: 0, skipped: new Map(),
    });
  }

  encrypt(plaintext, aad = Buffer.alloc(0)) {
    const step = kdfCk(this.s.chainSend);
    this.s.chainSend = step.chainKey;
    const header = new Header(this.s.dhSelf.publicBytes, this.s.pn, this.s.nSend);
    this.s.nSend += 1;
    const { encrypt } = require('./crypto');
    const blob = encrypt(step.messageKey, plaintext, Buffer.concat([Buffer.from(aad), header.toBytes()]));
    return { header, blob };
  }

  decrypt(header, blob, aad = Buffer.alloc(0)) {
    const { decrypt } = require('./crypto');
    const skippedKey = this._trySkipped(header);
    if (skippedKey) {
      return decrypt(skippedKey, blob, Buffer.concat([Buffer.from(aad), header.toBytes()]));
    }
    if (!this.s.dhRemote || !header.dh.equals(this.s.dhRemote)) {  // conversation turned
      this._skip(header.pn);
      this._dhRatchet(header);
    }
    this._skip(header.n);
    const step = kdfCk(this.s.chainRecv);
    this.s.chainRecv = step.chainKey;
    this.s.nRecv += 1;
    return decrypt(step.messageKey, blob, Buffer.concat([Buffer.from(aad), header.toBytes()]));
  }

  _dhRatchet(header) {
    this.s.pn = this.s.nSend;
    this.s.nSend = 0; this.s.nRecv = 0;
    this.s.dhRemote = Buffer.from(header.dh);
    let r = kdfRk(this.s.rootKey, dh(this.s.dhSelf, header.dh));
    this.s.rootKey = r.rootKey; this.s.chainRecv = r.chainKey;
    this.s.dhSelf = new DHKeyPair();
    r = kdfRk(this.s.rootKey, dh(this.s.dhSelf, header.dh));
    this.s.rootKey = r.rootKey; this.s.chainSend = r.chainKey;
  }

  _skip(until) {
    if (this.s.chainRecv === null) return;
    if (until - this.s.nRecv > MAX_SKIP) throw new Error('too many skipped messages');
    let ck = this.s.chainRecv;
    for (let i = this.s.nRecv; i < until; i++) {
      const step = kdfCk(ck);
      this.s.skipped.set(this.s.dhRemote.toString('hex') + ':' + i, step.messageKey);
      ck = step.chainKey;
    }
    if (until > this.s.nRecv) { this.s.chainRecv = ck; this.s.nRecv = until; }
  }

  _trySkipped(header) {
    const k = header.dh.toString('hex') + ':' + header.n;
    if (this.s.skipped.has(k)) {
      const mk = this.s.skipped.get(k);
      this.s.skipped.delete(k);
      return mk;
    }
    return null;
  }
}

module.exports = {
  Identity, x3dhInitiator, x3dhResponder, Header, DoubleRatchet, bundleToBytes,
};
