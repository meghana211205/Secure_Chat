'use strict';
/**
 * Proof that messages on the wire are unreadable.
 * Starts a relay, connects two clients, sends a known plaintext, and captures the raw
 * bytes crossing the TCP sockets (by tapping socket.write). It then shows the secret
 * does NOT appear in the transmitted bytes, while the recipient decrypts it exactly.
 */
const net = require('net');
const { RelayServer } = require('../src/server');
const { SecureChatClient } = require('../src/client');

const SECRET = 'ATTACK AT DAWN meet me at the old bridge';
const captured = [];
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// Tap every byte written to any TCP socket.
const origWrite = net.Socket.prototype.write;
net.Socket.prototype.write = function (data, ...rest) {
  if (Buffer.isBuffer(data)) captured.push(Buffer.from(data));
  else if (typeof data === 'string') captured.push(Buffer.from(data));
  return origWrite.call(this, data, ...rest);
};

(async () => {
  const server = new RelayServer('127.0.0.1', 0, { info: () => {} });
  const port = await server.listen();
  const alice = new SecureChatClient('alice', '127.0.0.1', port);
  const bob = new SecureChatClient('bob', '127.0.0.1', port);
  const received = [];
  bob.onMessage = (s, t) => received.push(t);
  await alice.connect(); await bob.connect();
  await sleep(100);
  captured.length = 0;                       // only capture the message exchange
  await alice.send('bob', SECRET);
  await sleep(300);
  alice.close(); bob.close(); await server.close();

  const onWire = Buffer.concat(captured);
  const line = '='.repeat(70);
  console.log(line);
  console.log('SECRET MESSAGE TYPED BY ALICE:\n   ' + JSON.stringify(SECRET));
  console.log('\nBOB DECRYPTED (on his machine):\n   ' +
    (received.length ? JSON.stringify(received[0]) : '<nothing>'));
  console.log('\nRAW BYTES CAPTURED ON THE NETWORK: ' + onWire.length + ' bytes');
  console.log('First 180 bytes of what actually crossed the wire:\n   ' +
    onWire.slice(0, 180).toString('hex'));
  console.log('\nSEARCH FOR THE SECRET IN THE CAPTURED TRAFFIC:');
  const hay = onWire.toString('latin1').toLowerCase();
  for (const probe of [SECRET, 'ATTACK', 'bridge', 'dawn']) {
    const present = hay.includes(probe.toLowerCase());
    console.log('   ' + (present ? 'FOUND (!)' : 'not present') + ': ' + JSON.stringify(probe));
  }
  const leaked = hay.includes(SECRET.toLowerCase());
  console.log('\nRESULT: ' + (leaked ? 'LEAK DETECTED'
    : 'the plaintext never appears on the wire; only ciphertext was transmitted.'));
  console.log(line);
  process.exit(received[0] === SECRET && !leaked ? 0 : 1);
})();
