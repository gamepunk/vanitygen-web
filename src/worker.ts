/**
 * Web Worker — vanity address search.
 *
 * Runs in a separate thread, receives search config via postMessage,
 * sends back progress updates and found results.
 */

import { sha256 } from "@noble/hashes/sha256";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { base58check, base58, bech32, bech32m } from "@scure/base";
import { secp256k1 as secp } from "@noble/curves/secp256k1";

// ── Constants ──────────────────────────────────────────────────────────

const MAINNET_PKH = 0x00;
const MAINNET_SH = 0x05;
const MAINNET_WIF = 0x80;
const PROGRESS_INTERVAL = 50_000;

// ── Codecs ─────────────────────────────────────────────────────────────

const b58check = base58check(sha256);

// ── Hashing ────────────────────────────────────────────────────────────

function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}
function dhash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}
function toHex(buf: Uint8Array): string {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ── Address derivation ─────────────────────────────────────────────────

function deriveAddress(privKey: Uint8Array, type: string): string {
  const pub = secp.getPublicKey(privKey, true);
  switch (type) {
    case "legacy": {
      const p = hash160(pub);
      return b58check.encode(Uint8Array.from([MAINNET_PKH, ...p]));
    }
    case "p2sh": {
      const kh = hash160(pub);
      const ws = new Uint8Array([0x00, 0x14, ...kh]);
      const sh = hash160(ws);
      return b58check.encode(Uint8Array.from([MAINNET_SH, ...sh]));
    }
    case "segwit": {
      const kh = hash160(pub);
      const data = new Uint8Array([0, ...kh]);
      return bech32.encode("bc", bech32.toWords(data), 90);
    }
    case "taproot": {
      const xOnly = pub.subarray(1);
      const data = new Uint8Array([1, ...xOnly]);
      return bech32m.encode("bc", bech32m.toWords(data), 90);
    }
    default:
      throw new Error("Unknown address type: " + type);
  }
}

function toWif(privKey: Uint8Array): string {
  const payload = new Uint8Array([MAINNET_WIF, ...privKey, 0x01]);
  const checksum = dhash256(payload).subarray(0, 4);
  return base58.encode(Uint8Array.from([...payload, ...checksum]));
}

// ── Address-type prefixes ──────────────────────────────────────────────

const ADDR_PREFIXES: Record<string, string> = {
  legacy: "1", p2sh: "3", segwit: "bc1q", taproot: "bc1p",
};

function stripPrefix(addr: string, addrType: string): string {
  const pfx = ADDR_PREFIXES[addrType];
  if (pfx && addr.startsWith(pfx)) return addr.slice(pfx.length);
  return addr;
}

// ── Matching ───────────────────────────────────────────────────────────

function isMatch(addr: string, pattern: string, mode: string, ci: boolean, addrType?: string, regex?: RegExp): boolean {
  let s = addrType ? stripPrefix(addr, addrType) : addr;
  if (ci) s = s.toLowerCase();
  const cmpPat = ci ? pattern.toLowerCase() : pattern;
  switch (mode) {
    case "prefix":   return s.startsWith(cmpPat);
    case "suffix":   return s.endsWith(cmpPat);
    case "anywhere": return s.includes(cmpPat);
    case "regex":    return regex?.test(addr) ?? false;
    default:         return false;
  }
}

// ── Search loop ─────────────────────────────────────────────────────────

function search(config: any, signal: { aborted: boolean }) {
  const { pattern, addressType, caseInsensitive, matchMode, targetCount, regexSource } = config;
  let regex: RegExp | undefined;
  if (matchMode === "regex" && regexSource) {
    try { regex = new RegExp(regexSource); } catch { return; }
  }
  const cmpPat = caseInsensitive ? pattern.toLowerCase() : pattern;
  let attempts = 0, found = 0;
  const start = performance.now();

  while (!signal.aborted && found < targetCount) {
    const privKey = secp.utils.randomPrivateKey();
    const addr = deriveAddress(privKey, addressType);
    attempts++;

    if (isMatch(addr, cmpPat, matchMode, caseInsensitive, addressType, regex)) {
      found++;
      const elapsed = performance.now() - start;
      self.postMessage({
        type: "found",
        result: {
          address: addr,
          wif: toWif(privKey),
          privateKeyHex: toHex(privKey),
          publicKeyHex: toHex(secp.getPublicKey(privKey, true)),
          attempts,
          workerId: config.workerId,
          elapsedMs: elapsed,
        },
      });
    }

    if (attempts % PROGRESS_INTERVAL === 0) {
      const elapsed = performance.now() - start;
      self.postMessage({
        type: "progress",
        workerId: config.workerId,
        attempts,
        rate: attempts / (elapsed / 1000),
        elapsedMs: elapsed,
      });
    }
  }
}

// ── Message handler ─────────────────────────────────────────────────────

let abortFlag = { aborted: false };

self.onmessage = (e: MessageEvent) => {
  const msg = e.data;
  if (msg.type === "stop") {
    abortFlag.aborted = true;
    return;
  }
  if (msg.type === "start") {
    abortFlag = { aborted: false };
    try {
      search(msg, abortFlag);
    } catch (err: any) {
      self.postMessage({ type: "error", workerId: msg.workerId, error: err.message });
    }
    self.postMessage({ type: "done", workerId: msg.workerId });
  }
};
