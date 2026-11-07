# SecureChat (Node.js): end-to-end encrypted chat with a Double Ratchet

A terminal chat application where messages are encrypted on the sender's machine and
decrypted only on the recipient's. The relay server in the middle sees nothing but
ciphertext. Each message uses a fresh key (a Signal-style Double Ratchet), so a key
compromised today cannot decrypt yesterday's messages (forward secrecy).

Node.js 16+. **No dependencies to install** — it uses only Node's built-in `crypto` and
`net` modules.

## Try it in three terminals

```bash
# 1. the relay server (sees only ciphertext)
node src/server.js

# 2. Alice
node src/chatapp.js --user alice --to bob

# 3. Bob
node src/chatapp.js --user bob --to alice
```

Type a line in either client and it appears, decrypted, in the other. Type `/quit` to exit.

## Prove it is actually encrypted

```bash
node scripts/capture_demo.js       # captures the raw wire bytes; the secret never appears
node scripts/demo_conversation.js  # readable walk-through of handshake, chat, forward secrecy
```

## Tests

```bash
node tests/run.js        # or: npm test
```

Eleven checks: crypto primitives, the handshake, the ratchet's security properties, and a
live two-client conversation through the real server over TCP.

## What is in the box

| File | Role |
|---|---|
| `src/crypto.js` | primitives: X25519 Diffie-Hellman, HKDF, AES-256-GCM |
| `src/ratchet.js` | X3DH handshake and the Double Ratchet (forward secrecy) |
| `src/protocol.js` | length-prefixed JSON wire frames |
| `src/server.js` | zero-knowledge relay: routes ciphertext by sender/recipient only |
| `src/client.js` | client; all encryption happens here |
| `src/chatapp.js` | interactive terminal UI |
| `scripts/capture_demo.js` | proof that plaintext never crosses the wire |
| `scripts/demo_conversation.js` | narrated protocol walk-through |
| `tests/` | crypto, handshake, ratchet and live end-to-end tests |

See `docs/PROJECT_REPORT.md` for the full write-up.

## Capturing with real tools

To prove it with Wireshark: capture on the loopback interface with filter
`tcp.port == 9999`, send a message, then right-click a packet and choose
Follow > TCP Stream. The `to`/`from` routing fields are visible but the `body` is
ciphertext. With tcpdump: `sudo tcpdump -A -i lo port 9999`.
