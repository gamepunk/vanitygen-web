# vanitygen

Bitcoin vanity address generator — **browser edition**.

Runs entirely in your browser. No server, no installation, no data leaves your machine.

All cryptographic operations use audited pure-JavaScript libraries:
[`@noble/secp256k1`](https://github.com/paulmillr/noble-secp256k1) and
[`bitcoinjs-lib`](https://github.com/bitcoinjs/bitcoinjs-lib).

---

## Usage

### Online

Open `index.html` in any modern browser (after building).

### Build & preview

```bash
# Install dependencies
bun install

# Build for production (minified)
bun run build

# Preview locally
bun run start
# → http://localhost:3000

# Or just open index.html directly in a browser
```

### Development

```bash
bun run dev    # watch mode, rebuilds on file changes
```

---

## Features

| Feature | Status |
|---------|--------|
| Address types: Legacy / P2SH / SegWit / Taproot | ✅ |
| Match modes: prefix / suffix / anywhere / regex | ✅ |
| Case-insensitive matching | ✅ |
| Multiple results (`-n` / count) | ✅ |
| WIF private key export | ✅ |
| Dark theme UI | ✅ |
| BIP39 mnemonic mode | 🚧 |
| Web Worker multi-threading | 🚧 |
| Input / output file support | 🚧 |

---

## Dependencies

```
vanitygen (browser)
├── @noble/secp256k1     — elliptic curve operations
├── bitcoinjs-lib        — Bitcoin address encoding
├── bs58                 — Base58Check encoding
├── bech32               — Bech32 / Bech32m encoding
└── bip39                — BIP39 mnemonic generation
```

All packages are pure JavaScript — no native bindings, no WASM.

---

## Project structure

```
src/
├── index.ts       — entry point, UI wiring
├── address.ts     — address derivation, WIF, matching logic
├── vanitygen.ts   — async search loop
└── style.css      — UI styles
```

---

## Disclaimer

**⚠ Use at your own risk.**

Private keys are generated and displayed in plain text in your browser.
Anyone with access to your screen or clipboard can steal your funds.

- **Move funds immediately** after the vanity address is funded.
- **Clear your clipboard** after copying private keys.
- The authors assume **no liability** for any loss of funds.

---

## License

MIT
