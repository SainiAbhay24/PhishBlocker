chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tabId = tabs[0]?.id;
  if (!tabId) return;
  chrome.storage.local.get([`last_result_${tabId}`], (data) => {
    const result = data[`last_result_${tabId}`];
    const el = document.getElementById("lastResult");
    if (result) {
      el.textContent = `Last scan: ${result.verdict} (${result.risk_score}/100)`;
    }
  });
});
