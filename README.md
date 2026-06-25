# vanitygen-web

Bitcoin vanity address generator — **browser edition**.

Runs entirely in your browser. No server, no installation, no data leaves your machine.

Also available as a native **Rust CLI** ([gamepunk/vanitygen](https://github.com/gamepunk/vanitygen)) for 10–100× faster generation.

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
| Address-type prefix auto-stripping | ✅ |
| Case-insensitive matching | ✅ |
| Multiple results (count) | ✅ |
| Web Worker parallel search | ✅ |
| Inline fallback (file:// protocol) | ✅ |
| Hidden private keys (click to reveal) | ✅ |
| Hidden BIP39 mnemonic (click to reveal) | ✅ |
| BIP39 mnemonic support | ✅ |
| Encrypt & download private key (AES-256-GCM + scrypt) | ✅ |
| Decrypt encrypted key file | ✅ |
| Plaintext export (no password) | ✅ |
| i18n with 14 languages | ✅ |
| Animated progress bar | ✅ |
| Close disclaimer / CLI sections | ✅ |
| Print paper wallet | ✅ |

---

## Dependencies

```
vanitygen-web (browser)
├── @noble/curves          — elliptic curve operations (secp256k1)
├── @noble/hashes          — SHA-256, RIPEMD-160, Scrypt
├── @scure/base            — Base58Check, Bech32, Bech32m
├── @scure/bip39           — BIP39 mnemonic generation
├── bech32                 — Bech32 / Bech32m encoding
└── bs58                   — Base58Check encoding (legacy)
```

All packages are pure JavaScript — no WASM, no native bindings.

---

## Project structure

```
src/
├── index.ts          — entry point, UI wiring, search orchestration
├── address.ts        — address derivation, WIF, matching logic
├── crypto.ts         — encrypt / decrypt (AES-256-GCM + scrypt)
├── modal.ts          — custom modal (prompt / alert)
├── i18n.ts           — internationalization (14 languages)
├── vanitygen.ts      — cooperative inline search loop
├── worker.ts         — Web Worker search loop
├── style.css         — UI styles
└── assets/           — static assets (images, favicon)
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
