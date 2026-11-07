'use strict';
// Two real clients talk through the real server over a real TCP socket.
const assert = require('assert');
const { RelayServer } = require('../src/server');
const { SecureChatClient } = require('../src/client');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function run() {
  const server = new RelayServer('127.0.0.1', 0, { info: () => {} });
  const port = await server.listen();
  const alice = new SecureChatClient('alice', '127.0.0.1', port);
  const bob = new SecureChatClient('bob', '127.0.0.1', port);
  const bobGot = [], aliceGot = [];
  bob.onMessage = (s, t) => bobGot.push([s, t]);
  alice.onMessage = (s, t) => aliceGot.push([s, t]);
  await alice.connect(); await bob.connect();
  await sleep(100);
  await alice.send('bob', 'Hello Bob, this is secret');
  await sleep(100);
  await bob.send('alice', 'Got it, Alice');
  await sleep(100);
  await alice.send('bob', 'Great, forward secrecy works');
  await sleep(150);

  assert.deepStrictEqual(bobGot[0], ['alice', 'Hello Bob, this is secret']);
  assert.deepStrictEqual(bobGot[1], ['alice', 'Great, forward secrecy works']);
  assert.deepStrictEqual(aliceGot[0], ['bob', 'Got it, Alice']);
  alice.close(); bob.close(); await server.close();
  console.log('  ok  end-to-end conversation through the server');
}

module.exports = { run };
if (require.main === module) run().then(() => console.log('integration passed'));
