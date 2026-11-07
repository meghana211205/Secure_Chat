'use strict';
/**
 * Interactive terminal chat client.
 *   Terminal 1:  node src/server.js
 *   Terminal 2:  node src/chatapp.js --user alice --to bob
 *   Terminal 3:  node src/chatapp.js --user bob --to alice
 * Type a line and press Enter to send. Type /quit to exit. Everything you type is
 * encrypted on THIS machine before it touches the network.
 */
const readline = require('readline');
const { SecureChatClient } = require('./client');

function arg(name, def) {
  const i = process.argv.indexOf(name);
  return i >= 0 ? process.argv[i + 1] : def;
}

(async () => {
  const user = arg('--user'), to = arg('--to');
  const host = arg('--host', '127.0.0.1'), port = Number(arg('--port', 9999));
  if (!user || !to) {
    console.log('usage: node src/chatapp.js --user <me> --to <peer> [--host H] [--port P]');
    process.exit(1);
  }
  const client = new SecureChatClient(user, host, port);
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const prompt = () => rl.setPrompt(`${user}> `), show = () => rl.prompt();
  client.onMessage = (sender, text) => {
    process.stdout.write(`\r${sender}: ${text}\n`);
    rl.prompt(true);
  };
  try {
    await client.connect();
  } catch {
    console.log(`Could not connect to the relay at ${host}:${port}. Is the server running?`);
    process.exit(1);
  }
  console.log(`Connected as '${user}'. Messaging '${to}'. Type a message (/quit to exit).`);
  prompt(); show();
  rl.on('line', async (line) => {
    line = line.trim();
    if (line === '/quit' || line === '/exit') { rl.close(); return; }
    if (line) {
      try { await client.send(to, line); }
      catch (e) { console.log(`[could not send: ${e.message}]`); }
    }
    show();
  });
  rl.on('close', () => { client.close(); console.log('bye'); process.exit(0); });
})();
