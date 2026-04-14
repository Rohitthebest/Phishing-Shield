async function loadCurrentTabResult() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  const messageEl = document.getElementById("message");
  const statusEl = document.getElementById("status");
  const urlEl = document.getElementById("url");

  if (!tab?.id) {
    messageEl.textContent = "No active tab found.";
    statusEl.textContent = "Unavailable";
    statusEl.className = "status error";
    return;
  }

  const storage = await chrome.storage.local.get(`tab:${tab.id}`);
  const result = storage[`tab:${tab.id}`];

  urlEl.textContent = tab.url || "";

  if (!result) {
    messageEl.textContent = "Open or refresh the website to analyze it.";
    statusEl.textContent = "Waiting";
    statusEl.className = "status skip";
    return;
  }

  messageEl.textContent = result.message || "No result available.";
  statusEl.textContent = result.verdict || "Unknown";
  statusEl.className = `status ${result.state || "skip"}`;
}

loadCurrentTabResult();
