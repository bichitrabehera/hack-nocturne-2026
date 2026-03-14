const params = new URLSearchParams(window.location.search);

const blockedUrl = params.get("url") || "Unknown URL";
const txHash = params.get("txHash") || "";
const category = params.get("category") || "unknown";
const riskScore = params.get("riskScore") || "—";

const frontendSimBase = "http://localhost:3000/sim";
const honeytrapLink = `${frontendSimBase}?url=${encodeURIComponent(blockedUrl)}&autoHoneytrap=1`;

const blockedUrlEl = document.getElementById("blockedUrl");
const txBoxEl = document.getElementById("txBox");
const txHashEl = document.getElementById("txHash");
const categoryEl = document.getElementById("category");
const riskScoreEl = document.getElementById("riskScore");
const honeytrapBtnEl = document.getElementById("honeytrapBtn");
const polygonscanBtnEl = document.getElementById("polygonscanBtn");
const goBackBtnEl = document.getElementById("goBackBtn");

if (blockedUrlEl) blockedUrlEl.textContent = blockedUrl;
if (categoryEl) categoryEl.textContent = category;
if (riskScoreEl) riskScoreEl.textContent = riskScore;
if (honeytrapBtnEl) honeytrapBtnEl.href = honeytrapLink;

if (txHash && txBoxEl && txHashEl && polygonscanBtnEl) {
  txBoxEl.style.display = "block";
  txHashEl.textContent = txHash;
  polygonscanBtnEl.style.display = "block";
  polygonscanBtnEl.href = `https://amoy.polygonscan.com/tx/${encodeURIComponent(txHash)}`;
}

if (goBackBtnEl) {
  goBackBtnEl.addEventListener("click", () => {
    window.history.back();
  });
}
