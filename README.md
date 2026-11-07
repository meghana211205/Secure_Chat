[README.md](https://github.com/user-attachments/files/34514510/README.md)
# Secure_Chat

End-to-end encrypted chat in Node.js. Messages are encrypted on the sender's device and decrypted only on the recipient's, so the relay server in the middle only ever sees ciphertext. It uses an **X3DH** key-agreement handshake and a Signal-style **Double Ratchet**, giving every message its own key and providing **forward secrecy**.

Built with only Node's built-in `crypto` and `net` modules, so there are no dependencies to install.

## Features

- **End-to-end encryption** — only the two chatting users can read the messages.
- **Zero-knowledge relay server** — routes messages by sender/recipient but cannot read them.
- **X3DH handshake** — two users derive a shared secret without ever transmitting it, and can start a session even when the other is offline.
- **Double Ratchet** — a fresh key for every message, giving forward secrecy and recovery after a key compromise.
- **Authenticated encryption (AES-256-GCM)** — any tampering with a message is detected.
- **Proof it works** — a capture script shows the plaintext never appears in the transmitted bytes.

## How it works

| Layer | What it does |
|---|---|
| X25519 Diffie-Hellman | two parties agree on a shared secret over a public channel |
| HKDF-SHA256 | derives per-message keys from that secret |
| AES-256-GCM | encrypts and authenticates each message |
| X3DH | the initial handshake that authenticates and seeds the session |
| Double Ratchet | advances the keys so each message is encrypted differently |

All encryption happens in the clients. The server reads only the `to` and `from` fields to route a message; the message body is opaque ciphertext.

## Requirements

- [Node.js](https://nodejs.org) 16 or newer (run `node --version` to check)

## Installation

```bash
git clone https://github.com/meghana211205/Secure_Chat.git
cd Secure_Chat
```

No `npm install` is needed; the project uses only Node's built-in modules.

## Usage

### Run the tests

```bash
node tests/run.js
```

Runs 11 checks covering the cryptography, the handshake, the ratchet's security properties, and a live two-client conversation.

### Live chat (three terminals)

```bash
# Terminal 1 — the relay server
node src/server.js

# Terminal 2 — Alice
node src/chatapp.js --user alice --to bob

# Terminal 3 — Bob
node src/chatapp.js --user bob --to alice
```

Type a line in either client and it appears, decrypted, in the other. Type `/quit` to exit.

### Prove it is actually encrypted

```bash
node scripts/capture_demo.js
node scripts/demo_conversation.js
```

`capture_demo.js` captures the raw wire bytes and shows the secret never appears. `demo_conversation.js` is a narrated walk-through of the handshake, a chat, and forward secrecy.

## Project structure

```
Secure_Chat/
├── src/
│   ├── crypto.js      # X25519 Diffie-Hellman, HKDF, AES-256-GCM
│   ├── ratchet.js     # X3DH handshake and the Double Ratchet
│   ├── protocol.js    # length-prefixed JSON wire frames
│   ├── server.js      # zero-knowledge relay server
│   ├── client.js      # client; all encryption happens here
│   └── chatapp.js     # interactive terminal UI
├── scripts/
│   ├── capture_demo.js
│   └── demo_conversation.js
├── tests/
├── docs/
│   └── PROJECT_REPORT.md
└── README.md
```

## Security scope

This is an educational implementation that demonstrates the real algorithms correctly. It is not a substitute for an audited messaging product. In particular, the signed prekey is not yet signed, so the handshake is not protected against a man-in-the-middle who controls the server; this is the first item of future work. The end-to-end encryption and forward-secrecy properties are real and demonstrated.

## License

MIT

## Acknowledgements

Based on the [X3DH](https://signal.org/docs/specifications/x3dh/) and [Double Ratchet](https://signal.org/docs/specifications/doubleratchet/) specifications by Signal.
