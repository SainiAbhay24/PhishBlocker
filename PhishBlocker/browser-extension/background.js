/**
 * PhishBlocker - Background Service Worker
 * ------------------------------------------
 * Intercepts pre-navigation events, sends the destination URL to the
 * PhishBlocker backend for analysis, and redirects to a local warning
 * page if the URL is scored WARN or BLOCK.
 *
 * This never blocks silently: the user always sees why a page was
 * flagged, matching the roadmap's "no false sense of 100% detection"
 * principle (Section 2 of the project doc).
 */

const API_BASE = "http://localhost:8000";

// Avoid re-checking the same URL twice in a row (webNavigation can fire
// more than once per navigation, e.g. on redirects).
const recentlyChecked = new Map(); // url -> timestamp
const DEDUPE_WINDOW_MS = 4000;

// Skip internal / non-http pages entirely.
function isCheckable(url) {
  return url.startsWith("http://") || url.startsWith("https://");
}

async function analyzeUrl(url) {
  const response = await fetch(`${API_BASE}/analyze`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, source: "browser_extension" }),
  });
  if (!response.ok) {
    throw new Error(`PhishBlocker API error: ${response.status}`);
  }
  return response.json();
}

chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  // Only inspect top-level frame navigations (not iframes/ads/etc.)
  if (details.frameId !== 0) return;
  const { url, tabId } = details;

  if (!isCheckable(url)) return;
  if (url.includes(chrome.runtime.getURL("warning.html"))) return; // don't re-scan our own warning page

  const now = Date.now();
  const last = recentlyChecked.get(url);
  if (last && now - last < DEDUPE_WINDOW_MS) return;
  recentlyChecked.set(url, now);

  try {
    const result = await analyzeUrl(url);
    console.log("[PhishBlocker] Analyzed:", url, result);

    await chrome.storage.local.set({
      [`last_result_${tabId}`]: result,
    });

    if (result.verdict === "BLOCK" || result.verdict === "WARN") {
      const warningUrl =
        chrome.runtime.getURL("warning.html") +
        `?target=${encodeURIComponent(url)}` +
        `&score=${result.risk_score}` +
        `&verdict=${result.verdict}` +
        `&severity=${result.severity}` +
        `&category=${encodeURIComponent(result.threat_category || "Suspicious Activity")}` +
        `&signals=${encodeURIComponent(JSON.stringify(result.signals))}`;

      chrome.tabs.update(tabId, { url: warningUrl });
    }
  } catch (err) {
    // Fail open but log -- in a production build you may prefer fail-closed
    // for high-security environments.
    console.error("[PhishBlocker] Analysis failed, allowing navigation:", err);
  }
});

// Badge feedback so the user can see PhishBlocker is active
chrome.runtime.onInstalled.addListener(() => {
  chrome.action.setBadgeText({ text: "ON" });
  chrome.action.setBadgeBackgroundColor({ color: "#2e7d32" });
});
