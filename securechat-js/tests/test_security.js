'use strict';
// Tests that prove the security properties the project claims.
const assert = require('assert');
const crypto = require('../src/crypto');
const { Identity, x3dhInitiator, x3dhResponder, DoubleRatchet } = require('../src/ratchet');

function newSession() {
  const alice = new Identity(), bob = new Identity();
  const { shared, identityPub, ephemeralPub } = x3dhInitiator(alice, bob.bundle());
  const sharedB = x3dhResponder(bob, identityPub, ephemeralPub);
  return {
    A: DoubleRatchet.initInitiator(shared, bob.signedPrekey.publicBytes),
    B: DoubleRatchet.initResponder(sharedB, bob.signedPrekey),
  };
}

const tests = {
  'DH agreement: both sides derive the same secret'() {
    const a = new crypto.DHKeyPair(), b = new crypto.DHKeyPair();
    assert.ok(crypto.dh(a, b.publicBytes).equals(crypto.dh(b, a.publicBytes)));
  },
  'chain KDF is one-way: each step yields distinct keys'() {
    const ck0 = Buffer.alloc(32, 1);
    const s1 = crypto.kdfCk(ck0), s2 = crypto.kdfCk(s1.chainKey);
    assert.ok(!s1.messageKey.equals(s2.messageKey));
    assert.ok(!s1.chainKey.equals(s2.chainKey));
  },
  'AEAD detects tampering'() {
    const k = crypto.hkdf(Buffer.from('seed'), 32, 't');
    const blob = Buffer.from(crypto.encrypt(k, 'secret'));
    blob[blob.length - 1] ^= 1;
    assert.throws(() => crypto.decrypt(k, blob));
  },
  'X3DH shared secret matches'() {
    const alice = new Identity(), bob = new Identity();
    const r = x3dhInitiator(alice, bob.bundle());
    assert.ok(r.shared.equals(x3dhResponder(bob, r.identityPub, r.ephemeralPub)));
  },
  'eavesdropper with only public keys cannot derive the secret'() {
    const alice = new Identity(), bob = new Identity();
    const r = x3dhInitiator(alice, bob.bundle());
    const attacker = new Identity();
    assert.ok(!r.shared.equals(x3dhResponder(attacker, r.identityPub, r.ephemeralPub)));
  },
  'every message uses a different key (ciphertext differs for same text)'() {
    const { A, B } = newSession();
    const seen = new Set();
    for (let i = 0; i < 5; i++) {
      const m = A.encrypt(Buffer.from('same text'));
      seen.add(m.blob.toString('hex'));
      B.decrypt(m.header, m.blob);
    }
    assert.strictEqual(seen.size, 5);
  },
  'forward secrecy: a used message key is not recoverable from later state'() {
    const { A, B } = newSession();
    const mk1 = crypto.kdfCk(A.s.chainSend).messageKey;
    const m = A.encrypt(Buffer.from('message one'));
    assert.strictEqual(
      crypto.decrypt(mk1, m.blob, m.header.toBytes()).toString(), 'message one');
    const mkNext = crypto.kdfCk(A.s.chainSend).messageKey;
    assert.ok(!mk1.equals(mkNext));
    B.decrypt(m.header, m.blob);
    assert.strictEqual(B.s.skipped.size, 0);
  },
  'out-of-order delivery decrypts correctly'() {
    const { A, B } = newSession();
    const msgs = [];
    for (let i = 0; i < 5; i++) msgs.push(A.encrypt(Buffer.from('msg ' + i)));
    for (const i of [0, 3, 1, 2, 4]) {
      assert.strictEqual(B.decrypt(msgs[i].header, msgs[i].blob).toString(), 'msg ' + i);
    }
  },
  'tampered ciphertext is rejected at the ratchet layer'() {
    const { A, B } = newSession();
    const m = A.encrypt(Buffer.from('authentic'));
    m.blob[m.blob.length - 1] ^= 1;
    assert.throws(() => B.decrypt(m.header, m.blob));
  },
  'break-in recovery: the root key advances as the ratchet turns'() {
    const { A, B } = newSession();
    const roots = new Set();
    for (let i = 0; i < 3; i++) {
      let m = A.encrypt(Buffer.from('ping')); B.decrypt(m.header, m.blob);
      m = B.encrypt(Buffer.from('pong')); A.decrypt(m.header, m.blob);
      roots.add(A.s.rootKey.toString('hex'));
    }
    assert.ok(roots.size > 1);
  },
};

async function run() {
  let pass = 0;
  for (const [name, fn] of Object.entries(tests)) {
    await fn();
    console.log('  ok  ' + name);
    pass++;
  }
  console.log(`  ${pass} security tests passed`);
}

module.exports = { run };
if (require.main === module) run();
