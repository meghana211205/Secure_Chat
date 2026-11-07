'use strict';
// Readable walk-through of the whole protocol, no network, for explaining the project.
const crypto = require('../src/crypto');
const { Identity, x3dhInitiator, x3dhResponder, DoubleRatchet } = require('../src/ratchet');
const L = (c = '=') => console.log(c.repeat(68));

console.log('SecureChat protocol walk-through\n');
L();
console.log('STEP 1  Identities and prekeys');
const alice = new Identity(), bob = new Identity();
console.log('  Alice identity public key: ' + alice.identity.publicBytes.toString('hex').slice(0, 32) + '...');
console.log('  Bob   identity public key: ' + bob.identity.publicBytes.toString('hex').slice(0, 32) + '...');
console.log('  Bob publishes a prekey bundle (public keys only) to the server.');

L();
console.log('STEP 2  X3DH handshake (Alice starts a session with Bob)');
const r = x3dhInitiator(alice, bob.bundle());
const sharedB = x3dhResponder(bob, r.identityPub, r.ephemeralPub);
console.log('  Alice derived shared secret: ' + r.shared.toString('hex').slice(0, 32) + '...');
console.log('  Bob   derived shared secret: ' + sharedB.toString('hex').slice(0, 32) + '...');
console.log('  Match: ' + r.shared.equals(sharedB) + '  (neither secret was ever sent over the wire)');

L();
console.log('STEP 3  Conversation (each message uses a brand-new key)');
const A = DoubleRatchet.initInitiator(r.shared, bob.signedPrekey.publicBytes);
const B = DoubleRatchet.initResponder(sharedB, bob.signedPrekey);
const script = [['A', 'Hi Bob'], ['A', 'Can you talk?'], ['B', 'Sure, go ahead'],
  ['A', 'Our link is end-to-end encrypted'], ['B', 'And forward-secret']];
for (const [who, text] of script) {
  if (who === 'A') {
    const m = A.encrypt(Buffer.from(text)); const out = B.decrypt(m.header, m.blob);
    console.log('  Alice -> Bob | wire: ' + m.blob.toString('hex').slice(0, 40) + '... | Bob reads: ' + JSON.stringify(out.toString()));
  } else {
    const m = B.encrypt(Buffer.from(text)); const out = A.decrypt(m.header, m.blob);
    console.log('  Bob -> Alice | wire: ' + m.blob.toString('hex').slice(0, 40) + '... | Alice reads: ' + JSON.stringify(out.toString()));
  }
}

L();
console.log('STEP 4  Forward secrecy');
const A2 = DoubleRatchet.initInitiator(r.shared, bob.signedPrekey.publicBytes);
const mk1 = crypto.kdfCk(A2.s.chainSend).messageKey;
A2.encrypt(Buffer.from('first message'));
const mkNext = crypto.kdfCk(A2.s.chainSend).messageKey;
console.log('  message 1 key: ' + mk1.toString('hex').slice(0, 32) + '...');
console.log('  key derivable from the chain AFTER message 1: ' + mkNext.toString('hex').slice(0, 32) + '...');
console.log('  message 1 key recoverable from later state? ' + mk1.equals(mkNext));
console.log('  The chain only moves forward, so a stolen later key cannot open past messages.');
L();
console.log('Done.');
