/**
 * Bitcoin address derivation for vanitygen-web.
 *
 * Uses audited pure-JS libraries:
 * - @noble/curves/secp256k1  — elliptic curve operations
 * - @noble/hashes     — SHA-256, RIPEMD-160
 * - @scure/base       — Base58Check, Bech32, Bech32m
 *
 * No WASM, no native bindings, no bitcoinjs-lib.
 */

import { secp256k1 as secp } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { base58, base58check, bech32, bech32m } from "@scure/base";
import { entropyToMnemonic } from "@scure/bip39";
import { wordlist } from "@scure/bip39/wordlists/english.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export enum AddressType {
  Legacy = "legacy",
  P2sh = "p2sh",
  Segwit = "segwit",
  Taproot = "taproot",
}

export enum MatchMode {
  Prefix = "prefix",
  Suffix = "suffix",
  Anywhere = "anywhere",
  Regex = "regex",
}

export interface FoundResult {
  address: string;
  wif: string;
  privateKeyHex: string;
  publicKeyHex: string;
  mnemonic?: string;
  attempts: number;
  workerId: number;
  elapsedMs: number;
}

export interface SearchConfig {
  pattern: string;
  addressType: AddressType;
  caseInsensitive: boolean;
  matchMode: MatchMode;
  targetCount: number;
  useMnemonic: boolean;
  words: number;
}

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

const MAINNET = {
  pubkeyhash: 0x00,
  scripthash: 0x05,
  wif: 0x80,
};

// ---------------------------------------------------------------------------
// Hashing helpers
// ---------------------------------------------------------------------------

/** RIPEMD160(SHA-256(input)) — aka HASH160 */
function hash160(data: Uint8Array): Uint8Array {
  return ripemd160(sha256(data));
}

/** SHA-256(SHA-256(input)) — double SHA-256 */
function dhash256(data: Uint8Array): Uint8Array {
  return sha256(sha256(data));
}

// Create Base58Check codec with sha256.
const b58check = base58check(sha256);

// ---------------------------------------------------------------------------
// Address derivation
// ---------------------------------------------------------------------------

/** Derive a Bitcoin address from a private key (32 bytes). */
export function deriveAddress(privKey: Uint8Array, type: AddressType): string {
  const pubCompressed = secp.getPublicKey(privKey, true); // 33 bytes

  switch (type) {
    case AddressType.Legacy: {
      const payload = hash160(pubCompressed);
      return b58check.encode(Uint8Array.from([MAINNET.pubkeyhash, ...payload]));
    }

    case AddressType.P2sh: {
      // P2SH-P2WPKH: HASH160 of witness script: 0x0014<HASH160(pubkey)>
      const keyHash = hash160(pubCompressed);
      const witnessScript = new Uint8Array([0x00, 0x14, ...keyHash]);
      const scriptHash = hash160(witnessScript);
      return b58check.encode(Uint8Array.from([MAINNET.scripthash, ...scriptHash]));
    }

    case AddressType.Segwit: {
      // P2WPKH: witness program = 0x00 + HASH160(pubkey)
      const keyHash = hash160(pubCompressed);
      const data = new Uint8Array([0, ...keyHash]);
      const words = bech32.toWords(data);
      return bech32.encode("bc", words, 90);
    }

    case AddressType.Taproot: {
      // P2TR: witness program = 0x01 + x-only pubkey (32 bytes)
      const xOnly = pubCompressed.subarray(1); // drop the 0x02/0x03 prefix
      const data = new Uint8Array([1, ...xOnly]);
      const words = bech32m.toWords(data);
      return bech32m.encode("bc", words, 90);
    }
  }
}

// ---------------------------------------------------------------------------
// WIF (Wallet Import Format)
// ---------------------------------------------------------------------------

/**
 * Encode a private key as WIF (compressed, mainnet).
 */
export function toWif(privKey: Uint8Array): string {
  const payload = new Uint8Array([MAINNET.wif, ...privKey, 0x01]);
  const checksum = dhash256(payload).subarray(0, 4);
  const withChecksum = new Uint8Array([...payload, ...checksum]);
  return base58.encode(withChecksum);
}

// ---------------------------------------------------------------------------
// Matching
// ---------------------------------------------------------------------------

/** Check if an address matches the given pattern and mode. */
export function addressTypePrefix(type: AddressType): string {
  switch (type) {
    case AddressType.Legacy: return "1";
    case AddressType.P2sh: return "3";
    case AddressType.Segwit: return "bc1q";
    case AddressType.Taproot: return "bc1p";
  }
}

export function stripAddressPrefix(address: string, type: AddressType): string {
  const prefix = addressTypePrefix(type);
  // The prefix might vary in length; just remove it if present
  if (address.startsWith(prefix)) return address.slice(prefix.length);
  return address;
}

export function isMatch(
  address: string,
  pattern: string,
  mode: MatchMode,
  caseInsensitive: boolean,
  addressType?: AddressType,
  regex?: RegExp,
): boolean {
  let s = addressType ? stripAddressPrefix(address, addressType) : address;
  if (caseInsensitive) s = s.toLowerCase();
  const cmpPat = caseInsensitive ? pattern.toLowerCase() : pattern;
  switch (mode) {
    case MatchMode.Prefix:
      return s.startsWith(cmpPat);
    case MatchMode.Suffix:
      return s.endsWith(cmpPat);
    case MatchMode.Anywhere:
      return s.includes(cmpPat);
    case MatchMode.Regex:
      return regex?.test(address) ?? false;
  }
}

// ---------------------------------------------------------------------------
// Key generation
// ---------------------------------------------------------------------------

/** Generate a cryptographically secure random 32-byte private key. */
export function randomPrivateKey(): Uint8Array {
  return secp.utils.randomPrivateKey();
}

/** Convert a Uint8Array to hex string. */
export function toHex(buf: Uint8Array): string {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** Parse a hex string to Uint8Array. */
export function fromHex(hex: string): Uint8Array {
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
  }
  return bytes;
}

// ---------------------------------------------------------------------------
// BIP39 mnemonic
// ---------------------------------------------------------------------------

/** Word count → entropy byte length */
export function wordsToEntropyBytes(words: number): number {
  return (words * 32) / 3; // 12→16, 15→20, 18→24, 21→28, 24→32
}

/** Generate random entropy of the appropriate size for the given word count. */
export function randomEntropy(words: number): Uint8Array {
  const len = wordsToEntropyBytes(words);
  const buf = new Uint8Array(len);
  crypto.getRandomValues(buf);
  return buf;
}

/** Convert entropy bytes to a BIP39 mnemonic phrase. */
export function entropyToMnemonicPhrase(entropy: Uint8Array): string {
  return entropyToMnemonic(entropy, wordlist);
}

/** Convert a private key (32 bytes) to a 24-word BIP39 mnemonic phrase. */
export function privateKeyToMnemonic(privKey: Uint8Array): string {
  return entropyToMnemonic(privKey, wordlist);
}

/** Convert a mnemonic phrase to a BIP39 seed (64 bytes) using Web Crypto API. */
export async function mnemonicToSeedWebcrypto(mnemonic: string): Promise<Uint8Array> {
  const { mnemonicToSeedWebcrypto: fn } = await import("@scure/bip39");
  return fn(mnemonic);
}

/**
 * Derive a BIP32 master private key from a seed.
 * This is the standard BIP32 master key derivation (HMAC-SHA512).
 * Returns the 32-byte private key.
 */
export async function deriveMasterKey(seed: Uint8Array): Promise<Uint8Array> {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode("Bitcoin seed"),
    { name: "HMAC", hash: "SHA-512" },
    false,
    ["sign"],
  );
  const hmac = await crypto.subtle.sign("HMAC", key, seed);
  return new Uint8Array(hmac.slice(0, 32));
}
