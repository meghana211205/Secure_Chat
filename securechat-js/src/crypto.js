'use strict';
/**
 * Cryptographic primitives. Thin wrappers over Node's built-in `crypto` module.
 *
 * Algorithms:
 *   X25519        - Elliptic-curve Diffie-Hellman key agreement (32-byte keys)
 *   HKDF-SHA256   - Turns a shared secret into uniformly-random key material (RFC 5869)
 *   AES-256-GCM   - Authenticated encryption: confidentiality AND tamper-detection
 *
 * We never implement the maths ourselves; we only compose vetted primitives.
 */
const crypto = require('crypto');

const KEY_LEN = 32;    // 256-bit symmetric keys
const NONCE_LEN = 12;  // 96-bit GCM nonce

// X25519 raw public keys are 32 bytes. Node wants DER/SPKI, so we prepend/strip
// the fixed 12-byte SPKI header to convert between raw bytes and key objects.
const SPKI_PREFIX = Buffer.from('302a300506032b656e032100', 'hex');

/** An X25519 key pair. The private half never leaves the owner. */
class DHKeyPair {
  constructor(keyObjects) {
    if (keyObjects) {
      this.privateKey = keyObjects.privateKey;
      this.publicKey = keyObjects.publicKey;
    } else {
      const kp = crypto.generateKeyPairSync('x25519');
      this.privateKey = kp.privateKey;
      this.publicKey = kp.publicKey;
    }
  }

  /** Raw 32-byte public key, suitable for sending over the wire. */
  get publicBytes() {
    return this.publicKey.export({ type: 'spki', format: 'der' }).slice(-KEY_LEN);
  }

  /** Raw 32-byte private key, for persistence/testing. */
  get privateBytes() {
    return this.privateKey.export({ type: 'pkcs8', format: 'der' }).slice(-KEY_LEN);
  }

  /** Shared secret with a peer's raw 32-byte public key. */
  exchange(peerPublicBytes) {
    return crypto.diffieHellman({
      privateKey: this.privateKey,
      publicKey: publicKeyFromBytes(peerPublicBytes),
    });
  }
}

/** Rebuild an X25519 public key object from 32 raw bytes. */
function publicKeyFromBytes(raw) {
  return crypto.createPublicKey({
    key: Buffer.concat([SPKI_PREFIX, Buffer.from(raw)]),
    format: 'der',
    type: 'spki',
  });
}

function dh(keyPair, peerPublicBytes) {
  return keyPair.exchange(peerPublicBytes);
}

/** Derive `length` bytes of key material from `inputKey`. */
function hkdf(inputKey, length, info, salt) {
  const out = crypto.hkdfSync(
    'sha256', inputKey, salt || Buffer.alloc(KEY_LEN), Buffer.from(info), length);
  return Buffer.from(out);
}

/** Root KDF: mix a fresh DH result into the root key. Returns {rootKey, chainKey}. */
function kdfRk(rootKey, dhOut) {
  const out = hkdf(dhOut, 2 * KEY_LEN, 'SecureChat-RootRatchet', rootKey);
  return { rootKey: out.slice(0, KEY_LEN), chainKey: out.slice(KEY_LEN) };
}

/** Chain KDF: advance a chain one step. Returns {chainKey, messageKey}. One-way. */
function kdfCk(chainKey) {
  return {
    chainKey: hkdf(chainKey, KEY_LEN, 'SecureChat-ChainNext'),
    messageKey: hkdf(chainKey, KEY_LEN, 'SecureChat-MsgKey'),
  };
}

/** Return nonce || ciphertext || tag. `aad` is authenticated, not encrypted. */
function encrypt(key, plaintext, aad = Buffer.alloc(0)) {
  const nonce = crypto.randomBytes(NONCE_LEN);
  const c = crypto.createCipheriv('aes-256-gcm', key, nonce);
  c.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([c.update(Buffer.from(plaintext)), c.final()]);
  return Buffer.concat([nonce, ct, c.getAuthTag()]);
}

/** Reverse of encrypt(). Throws if the key is wrong or the data was tampered with. */
function decrypt(key, blob, aad = Buffer.alloc(0)) {
  blob = Buffer.from(blob);
  const nonce = blob.slice(0, NONCE_LEN);
  const tag = blob.slice(blob.length - 16);
  const ct = blob.slice(NONCE_LEN, blob.length - 16);
  const d = crypto.createDecipheriv('aes-256-gcm', key, nonce);
  d.setAAD(Buffer.from(aad));
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}

module.exports = {
  KEY_LEN, NONCE_LEN, DHKeyPair, publicKeyFromBytes,
  dh, hkdf, kdfRk, kdfCk, encrypt, decrypt,
};
