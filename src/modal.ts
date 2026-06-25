/**
 * modal.ts — Custom modal (prompt / alert) for vanitygen-web.
 */

import { t } from "./i18n";

// ── DOM refs ────────────────────────────────────────────────────────────

const modalOverlay = document.getElementById("modalOverlay") as HTMLDivElement;
const modalTitle = document.getElementById("modalTitle") as HTMLDivElement;
const modalBody = document.getElementById("modalBody") as HTMLDivElement;
const modalConfirmBtn = document.getElementById("modalConfirmBtn") as HTMLButtonElement;
const modalCancelBtn = document.getElementById("modalCancelBtn") as HTMLButtonElement;

type ModalResolve<T> = (value: T) => void;

// ── Prompt ──────────────────────────────────────────────────────────────

export function showPrompt(question: string): Promise<string | null> {
  return new Promise((resolve: ModalResolve<string | null>) => {
    modalTitle.textContent = question;
    modalBody.innerHTML = `<input type="password" id="modalPasswordInput" placeholder="Enter password" autofocus />`;
    modalConfirmBtn.textContent = "OK";
    modalCancelBtn.textContent = t("keystoreCancel") || "Cancel";
    modalConfirmBtn.style.display = "";
    modalCancelBtn.style.display = "";
    modalOverlay.style.display = "flex";

    const input = document.getElementById("modalPasswordInput") as HTMLInputElement;
    input.focus();
    input.addEventListener("keydown", (e) => { if (e.key === "Enter") confirm(); if (e.key === "Escape") cancel(); });

    function cleanup() { modalOverlay.style.display = "none"; modalOverlay.removeEventListener("click", overlayClick); }
    function confirm() { cleanup(); resolve(input.value); }
    function cancel() { cleanup(); resolve(null); }

    modalConfirmBtn.onclick = confirm;
    modalCancelBtn.onclick = cancel;
    function overlayClick(e: MouseEvent) { if (e.target === modalOverlay) cancel(); }
    modalOverlay.addEventListener("click", overlayClick);
  });
}

// ── Alert ───────────────────────────────────────────────────────────────

export function showAlert(message: string, wif?: string): Promise<void> {
  return new Promise((resolve: ModalResolve<void>) => {
    const htmlMsg = message.replace(/\n/g, "<br>");
    if (wif) {
      modalTitle.textContent = t("decryptSuccess");
      modalBody.innerHTML = `<p>${htmlMsg}</p><span class="modal-wif">${wif}</span>`;
    } else {
      modalTitle.textContent = "";
      modalBody.innerHTML = `<p>${htmlMsg}</p>`;
    }
    modalConfirmBtn.textContent = "OK";
    modalCancelBtn.style.display = "none";
    modalOverlay.style.display = "flex";

    function cleanup() { modalOverlay.style.display = "none"; modalOverlay.removeEventListener("click", overlayClick); resolve(); }
    function overlayClick(e: MouseEvent) { if (e.target === modalOverlay) cleanup(); }
    modalConfirmBtn.onclick = cleanup;
    modalOverlay.addEventListener("click", overlayClick);
  });
}
