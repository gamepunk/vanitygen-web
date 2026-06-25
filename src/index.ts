/**
 * vanitygen-web — entry point.
 * Bootstraps the UI, wires up event handlers, manages Web Workers.
 */

import "./assets/style.css";
import { sha256 } from "@noble/hashes/sha256";
import { ripemd160 } from "@noble/hashes/ripemd160";
import { base58, base58check, bech32, bech32m } from "@scure/base";
import { secp256k1 as secp } from "@noble/curves/secp256k1";
import { AddressType, MatchMode, fromHex, type FoundResult, deriveAddress, toHex, privateKeyToMnemonic, selfTest, validatePrefix } from "./address";
import { t, switchLang, currentLang } from "./i18n";
import { showPrompt, showAlert } from "./modal";
import { generateEncryptedKey, decryptFile } from "./crypto";

// ── DOM refs ────────────────────────────────────────────────────────────

const $ = (id: string) => document.getElementById(id)!;
const patternInput = $("pattern") as HTMLInputElement;
const addressTypeSelect = $("addressType") as HTMLSelectElement;
const matchModeSelect = $("matchMode") as HTMLSelectElement;
const caseInsensitiveBtn = document.getElementById("caseInsensitiveBtn") as HTMLButtonElement;
const showMnemonicBtn = document.getElementById("showMnemonicBtn") as HTMLButtonElement;
const countInput = $("count") as HTMLInputElement;
const threadsInput = $("threads") as HTMLInputElement;
const startBtn = $("startBtn") as HTMLButtonElement;
const stopBtn = $("stopBtn") as HTMLButtonElement;
const progressEl = $("progress") as HTMLDivElement;
const progressBar = document.getElementById("progressBar") as HTMLDivElement;
const resultsEl = $("results") as HTMLDivElement;
const statusEl = $("status") as HTMLDivElement;
const wordsSelect = $("words") as HTMLSelectElement;

// ── State ───────────────────────────────────────────────────────────────

let workers: Worker[] = [];
let allResults: FoundResult[] = [];
let running = false;
let totalAttempts = 0;
let startTime = 0;
let inlineAbort = false;

const defaultThreads = Math.min(navigator.hardwareConcurrency || 4, 32);
threadsInput.value = String(defaultThreads);

// ── i18n ────────────────────────────────────────────────────────────────

function applyI18n() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n")!;
    const text = t(key);
    if (text && text !== key) {
      const tag = el.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA") {
        (el as HTMLInputElement).placeholder = text;
      } else if (tag === "OPTION") {
        (el as HTMLOptionElement).textContent = text;
      } else {
        el.textContent = text;
      }
    }
  });
  document.title = t("title");
  const pat = document.getElementById("pattern") as HTMLInputElement;
  if (pat) pat.placeholder = t("patternPlaceholder");
}
window.addEventListener("langchange", applyI18n);
applyI18n();

// ── Startup self-test ───────────────────────────────────────────────────
try {
  selfTest();
} catch (e) {
  console.error(e);
  statusEl.textContent = `Self-test failed: ${(e as Error).message}`;
}

const langSelect = document.getElementById("langSelect") as HTMLSelectElement;
if (langSelect) {
  langSelect.value = currentLang();
  langSelect.addEventListener("change", () => switchLang(langSelect.value));
}

function updateToggleText() {
  caseInsensitiveBtn.textContent = caseInsensitiveBtn.classList.contains("active") ? t("caseSensitive") : t("caseInsensitive");
  showMnemonicBtn.textContent = showMnemonicBtn.classList.contains("active") ? t("showMnemonicOn") : t("showMnemonicOff");
}
window.addEventListener("langchange", updateToggleText);
updateToggleText();
// Initialize words dropdown disabled state
wordsSelect.disabled = !showMnemonicBtn.classList.contains("active");

// ── Config ──────────────────────────────────────────────────────────────

patternInput.addEventListener("input", () => {
  patternInput.value = patternInput.value.replace(/[^a-zA-Z0-9$^.*+?{}()|[\]\\]/g, "").slice(0, 100);
});
patternInput.addEventListener("blur", () => { patternInput.value = patternInput.value.trim(); });

function getConfig() {
  const rawCount = parseInt(countInput.value, 10);
  return {
    pattern: patternInput.value.trim(),
    addressType: addressTypeSelect.value as AddressType,
    caseInsensitive: caseInsensitiveBtn.classList.contains("active"),
    matchMode: matchModeSelect.value as MatchMode,
    targetCount: isNaN(rawCount) || rawCount < 1 ? 1 : rawCount,
    threads: parseInt(threadsInput.value, 10) || defaultThreads,
  };
}

// ── Prefix display ──────────────────────────────────────────────────────

const prefixDisplay = document.getElementById("prefixDisplay") as HTMLInputElement;
const ADDR_PREFIXES: Record<string, string> = { legacy: "1", p2sh: "3", segwit: "bc1q", taproot: "bc1p" };

function updatePrefix() {
  prefixDisplay.value = ADDR_PREFIXES[addressTypeSelect.value] || "";
}
addressTypeSelect.addEventListener("change", updatePrefix);
updatePrefix();

// ── Helpers ─────────────────────────────────────────────────────────────

function formatElapsed(ms: number): string {
  if (ms < 1000) return `${ms.toFixed(0)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  const m = Math.floor(ms / 60_000);
  const s = Math.floor((ms % 60_000) / 1000);
  return `${m}m ${s}s`;
}

function deriveAllTypes(privKeyHex: string): Record<string, string> {
  const privKey = fromHex(privKeyHex);
  return {
    "Legacy (P2PKH)": deriveAddress(privKey, AddressType.Legacy),
    "Nested SegWit (P2SH)": deriveAddress(privKey, AddressType.P2sh),
    "Native SegWit (P2WPKH)": deriveAddress(privKey, AddressType.Segwit),
    "Taproot (P2TR)": deriveAddress(privKey, AddressType.Taproot),
  };
}

// ── Render result card ──────────────────────────────────────────────────

function renderResultCard(r: FoundResult, idx: number): string {
  const types = deriveAllTypes(r.privateKeyHex);
  const typesStr = Object.entries(types).map(([k, v]) => `  ${k}: ${v}`).join("\n");
  const wordCount = parseInt(wordsSelect.value, 10) || 24;
  const mnemonicHtml = r.mnemonic
    ? `<div class="mnemonic-box"><strong>${t("mnemonicTitle", wordCount)}</strong>
      <div style="display:flex;align-items:flex-start;gap:.4rem">
        <pre style="flex:1;margin:0"><span class="key-hidden" onclick="const s=this;if(s.classList.contains('key-revealed')){navigator.clipboard.writeText(s.textContent).then(()=>{const t=s.parentElement.nextElementSibling;const o=t.textContent;t.textContent='Copied!';setTimeout(()=>t.textContent=o,1500)})}else{s.classList.add('key-revealed');const b=s.parentElement.nextElementSibling;if(b&&b.classList.contains('reveal-btn'))b.textContent='${t("hide")}'}">${r.mnemonic}</span></pre>
        <button class="reveal-btn" onclick="const s=this.previousElementSibling.querySelector('.key-hidden');s.classList.toggle('key-revealed');this.textContent=s.classList.contains('key-revealed')?'${t("hide")}':'${t("reveal")}'">${t("reveal")}</button>
      </div></div>`
    : "";

  return `
    <div class="result-card">
      <h3>${t("match", idx)}</h3>
      ${mnemonicHtml}
      <table>
        <tr><td class="label">${t("address")}</td><td class="addr">${r.address}</td></tr>
        <tr><td class="label">${t("privateKey")}</td>
          <td class="mono"><span class="key-hidden" onclick="const s=this;if(s.classList.contains('key-revealed')){navigator.clipboard.writeText(s.textContent).then(()=>{const t=s.nextElementSibling;const o=t.textContent;t.textContent='Copied!';setTimeout(()=>t.textContent=o,1500)})}else{s.classList.add('key-revealed');const b=s.nextElementSibling;if(b&&b.classList.contains('reveal-btn'))b.textContent='${t("hide")}'}">${r.wif}</span>
          <button class="reveal-btn" onclick="const s=this.previousElementSibling;s.classList.toggle('key-revealed');this.textContent=s.classList.contains('key-revealed')?'${t("hide")}':'${t("reveal")}'">${t("reveal")}</button></td></tr>
        <tr><td class="label">${t("publicKey")}</td><td class="mono">${r.publicKeyHex}</td></tr>
        <tr><td class="label">${t("attempts")}</td><td>${r.attempts.toLocaleString()}</td></tr>
        <tr><td class="label">${t("time")}</td><td>${formatElapsed(r.elapsedMs)}</td></tr>
      </table>
      <div class="all-types"><strong>${t("allTypes")}</strong><pre>${typesStr}</pre></div>
      <button class="keystore-btn" data-wif="${r.wif}" data-mnemonic="${r.mnemonic ? r.mnemonic.replace(/"/g, '&quot;') : ''}">${t("keystoreBtn")}</button>
    </div>
  `;
}

// ── Workers / inline fallback ───────────────────────────────────────────

function createWorker(): Worker | null {
  try { return new Worker(new URL("./worker.js", import.meta.url)); }
  catch { return null; }
}

function stopAllWorkers() {
  for (const w of workers) { w.postMessage({ type: "stop" }); w.terminate(); }
  workers = [];
}

function runInlineSearch(
  config: ReturnType<typeof getConfig>,
  onFound: (r: FoundResult) => void,
  onProgress?: (attempts: number) => void,
  onDone?: () => void,
) {
  inlineAbort = false;
  const { pattern, addressType, caseInsensitive, matchMode, targetCount } = config;
  let regex: RegExp | undefined;
  if (matchMode === MatchMode.Regex) { try { regex = new RegExp(pattern); } catch {} }
  const cmpPat = caseInsensitive ? pattern.toLowerCase() : pattern;
  let attempts = 0, found = 0;
  const start = performance.now();

  const loop = () => {
    for (let i = 0; i < 50000; i++) {
      if (inlineAbort) { onDone?.(); return; }
      const privKey = new Uint8Array(32);
      crypto.getRandomValues(privKey);
      const pub = secp.getPublicKey(privKey, true);
      const h160 = (d: Uint8Array) => ripemd160(sha256(d));
      const b58ck = base58check(sha256);
      let addr: string;
      switch (addressType) {
        case AddressType.Legacy: addr = b58ck.encode(new Uint8Array([0x00, ...h160(pub)])); break;
        case AddressType.P2sh: addr = b58ck.encode(new Uint8Array([0x05, ...h160(new Uint8Array([0x00, 0x14, ...h160(pub)]))])); break;
        case AddressType.Segwit: addr = bech32.encode("bc", bech32.toWords(new Uint8Array([0, ...h160(pub)])), 90); break;
        case AddressType.Taproot: addr = bech32m.encode("bc", bech32m.toWords(new Uint8Array([1, ...pub.subarray(1)])), 90); break;
      }
      attempts++;
      // Strip address-type prefix before matching
      let matchAddr = addr;
      const pfx = ADDR_PREFIXES[addressType];
      if (pfx && matchAddr.startsWith(pfx)) matchAddr = matchAddr.slice(pfx.length);
      const s = caseInsensitive ? matchAddr.toLowerCase() : matchAddr;
      let match = false;
      if (matchMode === MatchMode.Prefix) match = s.startsWith(cmpPat);
      else if (matchMode === MatchMode.Suffix) match = s.endsWith(cmpPat);
      else if (matchMode === MatchMode.Anywhere) match = s.includes(cmpPat);
      else if (matchMode === MatchMode.Regex) match = regex?.test(addr) ?? false;
      if (match) {
        found++;
        const dhash = sha256(sha256(new Uint8Array([0x80, ...privKey, 0x01])));
        const wif = base58.encode(new Uint8Array([0x80, ...privKey, 0x01, ...dhash.subarray(0, 4)]));
        onFound({ address: addr, wif, privateKeyHex: toHex(privKey), publicKeyHex: toHex(pub), attempts, workerId: 0, elapsedMs: performance.now() - start });
        if (found >= targetCount) { onDone?.(); return; }
      }
    }
    onProgress?.(attempts);
    if (!inlineAbort) setTimeout(loop, 0); else onDone?.();
  };
  setTimeout(loop, 0);
}

// ── Progress helpers ────────────────────────────────────────────────────

function progressText(): string {
  const elapsed = performance.now() - startTime;
  const rate = totalAttempts / (elapsed / 1000);
  if (totalAttempts === 0) return `0 attempts · ${formatElapsed(elapsed)}`;
  return `${totalAttempts.toLocaleString()} attempts · ${rate.toFixed(0)} keys/s · ${formatElapsed(elapsed)}`;
}

function updateProgress() {
  progressEl.textContent = totalAttempts === 0 ? "searching..." : progressText();
}

function finishSearch() {
  progressBar.style.display = "none";
  running = false;
  startBtn.disabled = false;
  stopBtn.disabled = true;
  statusEl.textContent = allResults.length > 0 ? t("done", allResults.length) : t("tryShorter");
  progressEl.textContent = progressText();
}

// ── Start ───────────────────────────────────────────────────────────────

function handleFound(r: FoundResult, targetFound: number) {
  totalAttempts = Math.max(totalAttempts, r.attempts);
  updateProgress();
  if (showMnemonicBtn.classList.contains("active") && !r.mnemonic) {
    const wordCount = parseInt(wordsSelect.value, 10) || 24;
    const entropy = fromHex(r.privateKeyHex).slice(0, (wordCount * 32) / 3);
    r.mnemonic = privateKeyToMnemonic(entropy);
  }
  allResults.push(r);
  resultsEl.innerHTML += renderResultCard(r, allResults.length);
  resultsEl.scrollTop = resultsEl.scrollHeight;
  statusEl.textContent = t("found", allResults.length, targetFound);
  if (allResults.length >= targetFound) { stopAllWorkers(); inlineAbort = true; finishSearch(); }
}

startBtn.addEventListener("click", () => {
  const config = getConfig();
  if (!config.pattern) { statusEl.textContent = t("enterPattern"); return; }

  const validationError = validatePrefix(config.pattern, config.addressType as AddressType, config.caseInsensitive);
  if (validationError) {
    statusEl.textContent = `❌ ${validationError}`;
    progressBar.classList.remove("active");
    progressBar.style.display = "none";
    return;
  }

  const rs = document.getElementById("resultsSection");
  if (rs) rs.style.display = "";

  running = true;
  allResults = [];
  resultsEl.innerHTML = "";
  progressEl.textContent = "searching...";
  statusEl.textContent = "";
  progressBar.classList.add("active");
  progressBar.style.display = "";
  startBtn.disabled = true;
  stopBtn.disabled = false;
  totalAttempts = 0;
  startTime = performance.now();

  const workerCount = config.threads;
  let activeWorkers = workerCount;
  const targetFound = config.targetCount;

  for (let w = 0; w < workerCount; w++) {
    const worker = createWorker();
    if (!worker) { activeWorkers--; continue; }

    worker.onmessage = (e) => {
      const msg = e.data;
      if (msg.type === "found") handleFound(msg.result, targetFound);
      if (msg.type === "progress") { totalAttempts = Math.max(totalAttempts, msg.attempts); updateProgress(); }
      if (msg.type === "done") { activeWorkers--; if (activeWorkers <= 0) finishSearch(); }
      if (msg.type === "error") statusEl.textContent = `Worker Error: ${msg.error}`;
    };
    worker.onerror = () => { activeWorkers--; };
    worker.postMessage({
      type: "start",
      pattern: config.pattern,
      addressType: config.addressType,
      caseInsensitive: config.caseInsensitive,
      matchMode: config.matchMode,
      targetCount: config.targetCount,
      regexSource: config.matchMode === MatchMode.Regex ? config.pattern : undefined,
      workerId: w,
    });
    workers.push(worker);
  }

  if (workers.length === 0) {
    runInlineSearch(config,
      (r) => handleFound(r, targetFound),
      (a) => { totalAttempts = Math.max(totalAttempts, a); updateProgress(); },
      () => finishSearch(),
    );
  }

  const progressInterval = setInterval(() => {
    if (!running) clearInterval(progressInterval);
    else updateProgress();
  }, 500);
});

// ── Stop ────────────────────────────────────────────────────────────────

stopBtn.addEventListener("click", () => {
  running = false;
  inlineAbort = true;
  stopAllWorkers();
  progressBar.style.display = "none";
  startBtn.disabled = false;
  stopBtn.disabled = true;
  statusEl.textContent = t("stopped");
});

// ── Stepper buttons ────────────────────────────────────────────────────

const threadDec = document.getElementById("threadDec")!;
const threadInc = document.getElementById("threadInc")!;
function clampThreads() {
  let v = parseInt(threadsInput.value, 10);
  if (isNaN(v)) v = defaultThreads;
  threadsInput.value = String(Math.max(1, Math.min(32, v)));
}
threadDec.addEventListener("click", () => { threadsInput.value = String(Math.max(1, parseInt(threadsInput.value, 10) - 1)); });
threadInc.addEventListener("click", () => { threadsInput.value = String(Math.min(32, parseInt(threadsInput.value, 10) + 1)); });
threadsInput.addEventListener("change", clampThreads);
threadsInput.addEventListener("blur", clampThreads);

const countDec = document.getElementById("countDec")!;
const countInc = document.getElementById("countInc")!;
countDec.addEventListener("click", () => { countInput.value = String(Math.max(1, parseInt(countInput.value, 10) - 1)); });
countInc.addEventListener("click", () => { countInput.value = String(Math.min(100, parseInt(countInput.value, 10) + 1)); });

// ── Toggle buttons ─────────────────────────────────────────────────────

function toggleBtn(btn: HTMLButtonElement, keyOn: string, keyOff: string) {
  btn.classList.toggle("active");
  btn.textContent = btn.classList.contains("active") ? t(keyOn) : t(keyOff);
}
caseInsensitiveBtn.addEventListener("click", () => toggleBtn(caseInsensitiveBtn, "caseSensitive", "caseInsensitive"));
showMnemonicBtn.addEventListener("click", () => {
  toggleBtn(showMnemonicBtn, "showMnemonicOn", "showMnemonicOff");
  wordsSelect.disabled = !showMnemonicBtn.classList.contains("active");
});

// ── Encrypt / export ────────────────────────────────────────────────────

resultsEl.addEventListener("click", async (e) => {
  const btn = (e.target as HTMLElement).closest(".keystore-btn") as HTMLButtonElement | null;
  if (!btn) return;
  const wif = btn.dataset.wif;
  const mnemonic = btn.dataset.mnemonic || undefined;
  if (!wif) return;

  const password = await showPrompt(t("keystorePrompt"));
  if (password === null) return;

  btn.disabled = true;
  btn.textContent = "...";
  try {
    let blob: Blob;
    let suffix: string;
    if (password) {
      blob = await generateEncryptedKey(wif, mnemonic, password);
      suffix = "Encrypted";
    } else {
      const plain = JSON.stringify({ wif, mnemonic: mnemonic || null, createdAt: new Date().toISOString() }, null, 2);
      blob = new Blob([plain], { type: "application/json" });
      suffix = "Plaintext";
    }
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `Vanitygen-${suffix}-${wif.slice(0, 8)}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    btn.textContent = "Done";
    setTimeout(() => { btn.textContent = t("keystoreBtn"); btn.disabled = false; }, 2000);
  } catch (err) {
    console.error("Export error:", err);
    btn.textContent = "Error";
    setTimeout(() => { btn.textContent = t("keystoreBtn"); btn.disabled = false; }, 2000);
  }
});

// ── Decrypt file ────────────────────────────────────────────────────────

const decryptInput = document.getElementById("decryptInput") as HTMLInputElement;
const decryptBtn = document.getElementById("decryptBtn") as HTMLButtonElement;

decryptBtn.addEventListener("click", () => decryptInput.click());

decryptInput.addEventListener("change", async () => {
  const file = decryptInput.files?.[0];
  if (!file) return;
  decryptInput.value = "";

  const password = await showPrompt(t("decryptPrompt"));
  if (password === null) return;

  try {
    const decrypted = await decryptFile(file, password || "");
    const data = JSON.parse(decrypted);
    const wif = data.wif;
    const mnemonic = data.mnemonic;
    const addr = wif.startsWith("5") ? "Legacy" : wif.startsWith("K") || wif.startsWith("L") ? "SegWit" : "Unknown";
    let msg = `This is a ${addr} private key. Keep it safe!`;
    if (mnemonic) msg += `\n\nMnemonic: ${mnemonic}`;
    await showAlert(msg, wif);
  } catch {
    await showAlert(t("decryptError"));
  }
});

// ── Close buttons ───────────────────────────────────────────────────────

document.addEventListener("click", (e) => {
  const btn = (e.target as HTMLElement).closest(".close-btn") as HTMLButtonElement | null;
  if (!btn) return;
  const targetId = btn.dataset.target;
  if (targetId) {
    const el = document.getElementById(targetId);
    if (el) el.style.display = "none";
  }
});
