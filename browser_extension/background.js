const API_URL = "http://127.0.0.1:5000/predict";
const BADGE_STYLES = {
  safe: { text: "SAFE", color: "#057a6a" },
  phishing: { text: "PHISH", color: "#c63d3d" },
  invalid: { text: "BAD", color: "#e2871b" },
  error: { text: "OFF", color: "#6b7280" },
  skip: { text: "", color: "#6b7280" },
};

function isWebUrl(url) {
  return typeof url === "string" && /^https?:\/\//i.test(url);
}

async function storeResult(tabId, payload) {
  await chrome.storage.local.set({ [`tab:${tabId}`]: payload });
}

async function pushResultToPage(tabId, payload) {
  try {
    await chrome.tabs.sendMessage(tabId, {
      type: "phishingResult",
      payload,
    });
  } catch (error) {
    // Content script may not be ready yet.
  }
}

async function setBadge(tabId, state) {
  const badge = BADGE_STYLES[state] || BADGE_STYLES.error;
  await chrome.action.setBadgeText({ tabId, text: badge.text });
  await chrome.action.setBadgeBackgroundColor({ tabId, color: badge.color });
}

async function analyzeTab(tabId, url) {
  if (!isWebUrl(url)) {
    await setBadge(tabId, "skip");
    const payload = {
      state: "skip",
      url,
      verdict: "Unsupported",
      message: "This page type cannot be checked.",
    };
    await storeResult(tabId, payload);
    await pushResultToPage(tabId, payload);
    return;
  }

  try {
    const response = await fetch(API_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const result = await response.json();

    let state = "safe";
    let message = "This website looks safe.";

    if (!result.valid_url) {
      state = "invalid";
      message = result.format_checks?.[0] || "Invalid URL.";
    } else if (result.is_phishing) {
      state = "phishing";
      message = "This website looks like phishing.";
    }

    await setBadge(tabId, state);
    const payload = {
      state,
      url,
      verdict: result.verdict,
      riskLevel: result.risk_level,
      probability: result.phishing_probability,
      message,
    };
    await storeResult(tabId, payload);
    await pushResultToPage(tabId, payload);
  } catch (error) {
    await setBadge(tabId, "error");
    const payload = {
      state: "error",
      url,
      verdict: "Offline",
      message: "Start the Flask app at http://127.0.0.1:5000 first.",
    };
    await storeResult(tabId, payload);
    await pushResultToPage(tabId, payload);
  }
}

async function analyzeActiveTab() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (tab?.id) {
    analyzeTab(tab.id, tab.url);
  }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete") {
    analyzeTab(tabId, tab.url);
  }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
  const tab = await chrome.tabs.get(tabId);
  analyzeTab(tabId, tab.url);
});

chrome.webNavigation.onCompleted.addListener(({ tabId, url, frameId }) => {
  if (frameId === 0) {
    analyzeTab(tabId, url);
  }
});

chrome.windows.onFocusChanged.addListener(() => {
  analyzeActiveTab();
});

chrome.runtime.onInstalled.addListener(() => {
  analyzeActiveTab();
});

chrome.runtime.onStartup.addListener(() => {
  analyzeActiveTab();
});

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message?.type !== "getCurrentAnalysis") {
    return false;
  }

  const tabId = sender.tab?.id;
  if (!tabId) {
    sendResponse(null);
    return false;
  }

  chrome.storage.local.get(`tab:${tabId}`).then((storage) => {
    sendResponse(storage[`tab:${tabId}`] || null);
  });
  return true;
});
