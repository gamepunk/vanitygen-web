/**
 * crypto.ts — Encrypt / decrypt private keys for vanitygen-web.
 *
 * Encryption: AES-256-GCM with scrypt key derivation.
 */

import { scrypt } from "@noble/hashes/scrypt";
import { fromHex, toHex } from "./address";

// ── Encrypt ─────────────────────────────────────────────────────────────

export async function generateEncryptedKey(wif: string, mnemonic: string | undefined, password: string): Promise<Blob> {
  const salt = crypto.getRandomValues(new Uint8Array(32));
  const iv = crypto.getRandomValues(new Uint8Array(12)); // 96-bit IV for GCM

  // Derive 32-byte key using scrypt
  const derivedKey = scrypt(password.normalize("NFKD"), salt, { N: 262144, r: 8, p: 1, dkLen: 32 });

  // Build plaintext JSON with wif + optional mnemonic
  const plain = JSON.stringify({ wif, mnemonic: mnemonic || null });
  const key = await crypto.subtle.importKey("raw", derivedKey, { name: "AES-GCM" }, false, ["encrypt"]);
  const encrypted = new Uint8Array(
    await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(plain))
  );
  // GCM appends 16-byte auth tag at the end
  const ciphertext = encrypted.slice(0, -16);
  const tag = encrypted.slice(-16);

  const payload = {
    title: "Vanitygen Encrypted Private Key",
    network: "Bitcoin",
    createdAt: new Date().toISOString(),
    algorithm: "AES-256-GCM",
    kdf: "scrypt",
    kdfParams: { N: 262144, r: 8, p: 1, dkLen: 32, salt: toHex(salt) },
    cipherParams: { iv: toHex(iv), tag: toHex(tag) },
    ciphertext: toHex(ciphertext),
  };

  return new Blob([JSON.stringify(payload, null, 2)], { type: "application/json" });
}

// ── Decrypt ─────────────────────────────────────────────────────────────

export async function decryptFile(file: File, password: string): Promise<string> {
  const json = JSON.parse(await file.text());
  // Plaintext export has no algorithm field
  if (!json.algorithm) return JSON.stringify(json);
  const salt = fromHex(json.kdfParams.salt);
  const iv = fromHex(json.cipherParams.iv);
  const tag = fromHex(json.cipherParams.tag);
  const ciphertext = fromHex(json.ciphertext);

  const derivedKey = scrypt(password.normalize("NFKD"), salt, { N: json.kdfParams.N, r: json.kdfParams.r, p: json.kdfParams.p, dkLen: json.kdfParams.dkLen });
  const key = await crypto.subtle.importKey("raw", derivedKey, { name: "AES-GCM" }, false, ["decrypt"]);
  const decrypted = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, Uint8Array.of(...ciphertext, ...tag));
  return new TextDecoder().decode(decrypted);
}
