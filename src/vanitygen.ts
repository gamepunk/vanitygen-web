/**
 * vanitygen-web — Bitcoin vanity address generator (browser edition).
 *
 * Core search logic.  Runs asynchronously with cooperative multitasking
 * (setTimeout) so the UI stays responsive.
 */

import { secp256k1 as secp } from "@noble/curves/secp256k1";
import {
  deriveAddress,
  isMatch,
  randomPrivateKey,
  toWif,
  MatchMode,
  AddressType,
  type SearchConfig,
  type FoundResult,
} from "./address";

// ---------------------------------------------------------------------------
// Search runner
// ---------------------------------------------------------------------------

export type ProgressCallback = (info: {
  attempts: number;
  rate: number;
  elapsedMs: number;
}) => void;

export type FoundCallback = (result: FoundResult) => void;

export type ErrorCallback = (error: string) => void;

/** Run a vanity search with cooperative multi-tasking. */
export function search(
  config: SearchConfig,
  onProgress: ProgressCallback,
  onFound: FoundCallback,
  onError: ErrorCallback,
  signal?: AbortSignal,
): Promise<void> {
  return new Promise((resolve) => {
    const { pattern, addressType, caseInsensitive, matchMode, targetCount } = config;

    // Pre-compile regex.
    let regex: RegExp | undefined;
    if (matchMode === MatchMode.Regex) {
      try {
        regex = new RegExp(pattern);
      } catch (e) {
        onError(`Invalid regex: ${e}`);
        resolve();
        return;
      }
    }

    const cmpPat = caseInsensitive ? pattern.toLowerCase() : pattern;

    let attempts = 0;
    const startTime = performance.now();
    let found = 0;
    const batchSize = 100_000;

    const loop = (): void => {
      for (let i = 0; i < batchSize; i++) {
        if (signal?.aborted) { resolve(); return; }

        const privKey = randomPrivateKey();
        const addr = deriveAddress(privKey, addressType);
        attempts++;

        if (isMatch(addr, cmpPat, matchMode, caseInsensitive, addressType, regex)) {
          const elapsedMs = performance.now() - startTime;
          onFound({
            address: addr,
            wif: toWif(privKey),
            privateKeyHex: toHex(privKey),
            publicKeyHex: toHex(secp.getPublicKey(privKey, true)),
            attempts,
            workerId: 0,
            elapsedMs,
          });
          found++;
          if (found >= targetCount) { resolve(); return; }
        }
      }

      if (signal?.aborted) { resolve(); return; }

      // Report progress.
      const elapsedMs = performance.now() - startTime;
      const rate = attempts / (elapsedMs / 1000);
      onProgress({ attempts, rate, elapsedMs });

      // Yield to event loop.
      setTimeout(loop, 0);
    };

    setTimeout(loop, 0);
  });
}

function toHex(buf: Uint8Array): string {
  return Array.from(buf).map((b) => b.toString(16).padStart(2, "0")).join("");
}

