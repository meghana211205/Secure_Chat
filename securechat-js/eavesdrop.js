'use strict';
const net = require('net');
const LISTEN = 9998, SERVER = 9999;

net.createServer((client) => {
  const upstream = net.createConnection(SERVER, '127.0.0.1');
  const show = (dir, data) => {
    console.log('\n--- ' + dir + ' ' + data.length + ' bytes on the wire ---');
    console.log(data.toString('hex'));
    const readable = data.toString('latin1').match(/[\x20-\x7e]{4,}/g);
    if (readable) console.log('readable fragments:', readable.join(' | '));
  };
  client.on('data', (d) => { show('client -> server', d); upstream.write(d); });
  upstream.on('data', (d) => { show('server -> client', d); client.write(d); });
  client.on('close', () => upstream.end());
  upstream.on('close', () => client.end());
  client.on('error', () => {});
  upstream.on('error', () => {});
}).listen(LISTEN, '127.0.0.1', () =>
  console.log('Eavesdropper listening on ' + LISTEN + ', forwarding to the real server on ' + SERVER + '.'));