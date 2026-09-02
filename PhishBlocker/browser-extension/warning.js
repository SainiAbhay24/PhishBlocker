/**
 * PhishBlocker - Warning Page Controller
 * Reads the analysis result passed via query params and renders it,
 * then wires up the "go back" / "proceed anyway" actions.
 */
const params = new URLSearchParams(window.location.search);

const targetUrl = params.get("target") || "";
const score = params.get("score") || "0";
const verdict = params.get("verdict") || "WARN";
const severity = params.get("severity") || "MEDIUM";
const category = params.get("category") || "Suspicious Activity";
let signals = [];
try {
  signals = JSON.parse(params.get("signals") || "[]");
} catch (e) {
  signals = [];
}

document.getElementById("banner").classList.add(severity);
document.getElementById("bannerText").textContent =
  verdict === "BLOCK" ? "THREAT DETECTED — BLOCKED" : "SUSPICIOUS SITE — PROCEED WITH CAUTION";
document.getElementById("scoreValue").textContent = `${score}/100`;
document.getElementById("verdictBadge").textContent = category;
document.getElementById("targetUrl").textContent = targetUrl;

const list = document.getElementById("signalsList");
if (signals.length === 0) {
  const li = document.createElement("li");
  li.textContent = "General risk heuristics triggered.";
  list.appendChild(li);
} else {
  signals.forEach((s) => {
    const li = document.createElement("li");
    const label = document.createElement("span");
    label.textContent = s.detail;
    const weight = document.createElement("span");
    weight.className = "weight";
    weight.textContent = `+${s.weight}`;
    li.appendChild(label);
    li.appendChild(weight);
    list.appendChild(li);
  });
}

document.getElementById("backBtn").addEventListener("click", () => {
  // Send the user somewhere safe instead of just history.back(),
  // since history.back() could loop right into the same redirect chain.
  window.location.href = "https://www.google.com";
});

document.getElementById("proceedBtn").addEventListener("click", () => {
  if (confirm("Are you sure? This site was flagged as risky by PhishBlocker.")) {
    window.location.href = targetUrl;
  }
});
