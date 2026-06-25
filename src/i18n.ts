/**
 * i18n — lightweight internationalization for vanitygen.
 *
 * Usage:
 *   import { t, setLang, currentLang } from "./i18n";
 *   t("pattern")       // → "Pattern" or "模式" depending on current language
 *   setLang("zh-CN")   // switch to Chinese
 */

const LANGUAGES: Record<string, Record<string, string>> = {
  "en": {
    // Meta
    lang: "English",
    title: "Vanitygen",
    subtitle: "Bitcoin vanity address generator — runs entirely in your browser",

    // Controls
    pattern: "Pattern",
    addressType: "Address Type",
    matchMode: "Match Mode",
    count: "Count",
    threads: "Threads",
    caseLabel: "Case",
    caseInsensitive: "Case-insensitive",
    caseSensitive: "Case-sensitive",
    showMnemonic: "Mnemonic",
    showMnemonicOn: "Show Mnemonic",
    showMnemonicOff: "Hide Mnemonic",
    words: "Mnemonic Words",
    importLabel: "📂 Import patterns from file",
    importTemplate: "📄 Download template",

    // Match modes
    prefix: "Prefix",
    suffix: "Suffix",
    anywhere: "Anywhere",
    regex: "Regex",

    // Address types
    legacy: "Legacy (P2PKH)",
    p2sh: "Nested SegWit (P2SH)",
    segwit: "Native SegWit (P2WPKH)",
    taproot: "Taproot (P2TR)",

    // Buttons
    start: "Start Search",
    stop: "Stop",
    export: "Export",
    print: "Print",
    reveal: "Reveal",
    hide: "Hide",

    // Status
    emptyState: "Enter a pattern and click Start to find your vanity address.",
    enterPattern: "Please enter a pattern.",
    found: (n: number, t: number) => `Found ${n}/${t} address(es)`,
    done: (n: number) => `Done — found ${n} address(es)`,
    stopped: "Stopped.",
    tryShorter: "Done — found 0 address(es). Try a shorter pattern.",
    loadedPatterns: (n: number) => `Loaded ${n} pattern(s). Edit or click Start.`,

    // Result card
    match: (n: number) => `Match #${n}`,
    address: "Address",
    wif: "WIF",
    privateKey: "Private Key",
    publicKey: "Public Key",
    attempts: "Attempts",
    time: "Time",
    allTypes: "All address types (same key):",
    mnemonicTitle: (n: number) => `BIP39 Mnemonic (${n} words):`,
    keystoreBtn: "Encrypt & Download",
    keystorePrompt: "Enter a password to encrypt the private key:",
    keystoreError: "Encryption failed.",
    keystoreCancel: "Cancel",
    decryptBtn: "Decrypt File",
    decryptPrompt: "Enter the password to decrypt:",
    decryptSuccess: "Decrypted WIF:",
    decryptError: "Wrong password or corrupted file.",

    // Print
    printTitle: "Vanity Address — Paper Wallet",
    printAddress: "Bitcoin Address",
    printPrivate: "Private Key (WIF)",
    printWarning: "Keep this key offline! Anyone with this key can steal your funds.",

    // Footer
    footerDonate: "Donate: bc1q... (coming soon)",
    footerGitHub: "GitHub",

    // Security & Disclaimer
    secTitle: "Security",
    secHow: "How it works",
    secHowText: "Your browser generates random private keys locally and derives Bitcoin addresses until it finds one matching your pattern. All computations happen entirely in your browser tab — nothing is sent over the network.",
    secOffline: "100% Offline",
    secOfflineText: "After the page loads, you can disconnect from the internet and continue using it seamlessly. You can also download the page and run it on an air-gapped computer for maximum security.",
    secOpenSource: "Open Source",
    secOpenSourceText: "The source code is fully available on GitHub for review. You can inspect exactly what the tool does before using it.",
    secRandom: "Cryptographically Secure",
    secRandomText: "Key generation uses the browser's built-in cryptographically secure pseudo-random number generator (CSPRNG) via crypto.getRandomValues().",
    disclaimerTitle: "Disclaimer",
    disclaimerText: "This tool is provided as-is, without any warranty. You are solely responsible for the security of your private keys. Always verify generated addresses before use. The authors are not liable for any loss or damage arising from the use of this tool. For maximum security, generate keys on an offline, air-gapped computer.",
  },

  "es": { lang: "Español" },
  "fr": { lang: "Français" },
  "el": { lang: "ελληνικά" },
  "it": { lang: "italiano" },
  "de": { lang: "Deutsch" },
  "cs": { lang: "Česky" },
  "hu": { lang: "Magyar" },
  "ja": { lang: "日本語" },
  "zh-TW": { lang: "繁体中文" },
  "ru": { lang: "Русский" },
  "pt": { lang: "português" },

  "zh-CN": {
    lang: "简体中文",
    title: "Vanitygen",
    subtitle: "比特币虚荣地址生成器 — 完全在浏览器中运行",

    pattern: "模式",
    addressType: "地址类型",
    matchMode: "匹配模式",
    count: "数量",
    threads: "线程",
    caseLabel: "大小写",
    caseInsensitive: "不区分大小写",
    caseSensitive: "区分大小写",
    showMnemonic: "助记词",
    showMnemonicOn: "显示助记词",
    showMnemonicOff: "不显示助记词",
    words: "助记词单词数",
    importLabel: "📂 从文件导入模式",
    importTemplate: "📄 下载模板",

    prefix: "前缀",
    suffix: "后缀",
    anywhere: "子串",
    regex: "正则",

    legacy: "Legacy (P2PKH)",
    p2sh: "Nested SegWit (P2SH)",
    segwit: "Native SegWit (P2WPKH)",
    taproot: "Taproot (P2TR)",

    start: "开始搜索",
    stop: "停止",
    export: "导出",
    print: "打印",
    reveal: "点击后显示",
    hide: "点击后隐藏",

    emptyState: "输入模式后点击开始搜索您的虚荣地址。",
    enterPattern: "请输入模式。",
    found: (n: number, t: number) => `已找到 ${n}/${t} 个地址`,
    done: (n: number) => `完成 — 找到 ${n} 个地址`,
    stopped: "已停止。",
    tryShorter: "完成 — 未找到匹配地址。请尝试更短的模式。",
    loadedPatterns: (n: number) => `已加载 ${n} 个模式。编辑后点击开始。`,

    match: (n: number) => `匹配 #${n}`,
    address: "地址",
    wif: "WIF",
    privateKey: "私钥",
    publicKey: "公钥",
    attempts: "尝试次数",
    time: "用时",
    allTypes: "同一密钥的全部地址类型：",
    mnemonicTitle: (n: number) => `助记词（${n}个单词）：`,
    keystoreBtn: "加密导出",
    keystorePrompt: "输入密码加密私钥：",
    keystoreError: "加密失败。",
    keystoreCancel: "取消",
    decryptBtn: "解密文件",
    decryptPrompt: "输入密码解密：",
    decryptSuccess: "解密后的 WIF：",
    decryptError: "密码错误或文件损坏。",

    printTitle: "虚荣地址 — 纸钱包",
    printAddress: "比特币地址",
    printPrivate: "私钥 (WIF)",
    printWarning: "离线保存此密钥！任何人拥有此密钥即可窃取你的资金。",

    // Footer
    footerDonate: "捐赠: bc1q... (即将上线)",
    footerGitHub: "GitHub",

    // Security & Disclaimer
    secTitle: "安全性",
    secHow: "工作原理",
    secHowText: "您的浏览器在本地生成随机私钥并推导比特币地址，直到找到匹配您模式的地址。所有计算完全在您的浏览器标签页中完成 — 没有任何数据通过网络发送。",
    secOffline: "100% 离线",
    secOfflineText: "页面加载完成后，您可以断开互联网连接并继续无缝使用。您也可以下载此页面，在离线计算机上运行以获得最高安全性。",
    secOpenSource: "开源代码",
    secOpenSourceText: "源代码完全在 GitHub 上公开，可供审查。您可以在使用前完整检查工具的行为。",
    secRandom: "密码安全",
    secRandomText: "密钥生成使用浏览器内置的密码学安全伪随机数生成器（CSPRNG），通过 crypto.getRandomValues() 实现。",
    disclaimerTitle: "免责声明",
    disclaimerText: "本工具按「原样」提供，不附带任何担保。您对自己的私钥安全负全部责任。使用前请务必验证生成的地址。作者不对因使用本工具造成的任何损失或损害承担责任。为获得最高安全性，请在离线的、不联网的计算机上生成密钥。",
  },
};

// ── Current language ────────────────────────────────────────────────────

let current: string = "en";

function detectLang(): string {
  const navLang = navigator.language || (navigator as any).userLanguage || "";
  const supported = Object.keys(LANGUAGES);
  // Exact match first (zh-CN → zh-CN, zh-TW → zh-TW)
  if (supported.includes(navLang)) return navLang;
  // Try base language (de → de, fr → fr, etc.)
  const base = navLang.split("-")[0];
  if (supported.includes(base)) return base;
  // Chinese variants: simplified → zh-CN, traditional → zh-TW
  if (base === "zh") {
    const region = navLang.split("-")[1] || "";
    const tradRegions = ["TW", "HK", "MO"];
    return tradRegions.includes(region) ? "zh-TW" : "zh-CN";
  }
  // Fallback
  return "en";
}

// ── Public API ──────────────────────────────────────────────────────────

export function currentLang(): string {
  return current;
}

export function setLang(lang: string) {
  if (LANGUAGES[lang]) current = lang;
}

export function t(key: string, ...args: any[]): string {
  const entry = LANGUAGES[current]?.[key] ?? LANGUAGES["en"]?.[key] ?? key;
  return typeof entry === "function" ? entry(...args) : entry;
}

export function switchLang(lang: string) {
  setLang(lang);
  const docLang = lang === "zh-CN" ? "zh" : lang === "zh-TW" ? "zh-TW" : "en";
  document.documentElement.lang = docLang;
  // Dispatch event for UI to update
  window.dispatchEvent(new CustomEvent("langchange", { detail: lang }));
}

// Initialize
setLang(detectLang());
document.documentElement.lang = "en";
