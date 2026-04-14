const BANNER_ID = "phishing-shield-banner";

function bannerStyles(state) {
  const palette = {
    safe: {
      background: "#ecfdf5",
      color: "#065f46",
      border: "#a7f3d0",
      label: "SAFE",
    },
    phishing: {
      background: "#fef2f2",
      color: "#991b1b",
      border: "#fecaca",
      label: "PHISHING",
    },
    invalid: {
      background: "#fffbeb",
      color: "#92400e",
      border: "#fde68a",
      label: "INVALID",
    },
    error: {
      background: "#f3f4f6",
      color: "#374151",
      border: "#d1d5db",
      label: "OFFLINE",
    },
    skip: {
      background: "#f3f4f6",
      color: "#374151",
      border: "#d1d5db",
      label: "SKIP",
    },
  };
  return palette[state] || palette.error;
}

function ensureBanner() {
  let banner = document.getElementById(BANNER_ID);
  if (banner) {
    return banner;
  }

  banner = document.createElement("div");
  banner.id = BANNER_ID;
  banner.style.position = "fixed";
  banner.style.right = "16px";
  banner.style.bottom = "16px";
  banner.style.zIndex = "2147483647";
  banner.style.maxWidth = "320px";
  banner.style.padding = "12px 14px";
  banner.style.borderRadius = "8px";
  banner.style.border = "1px solid #d1d5db";
  banner.style.boxShadow = "0 14px 32px rgba(15, 23, 42, 0.18)";
  banner.style.fontFamily = "Arial, Helvetica, sans-serif";
  banner.style.lineHeight = "1.4";
  banner.style.fontSize = "14px";
  banner.style.background = "#ffffff";
  banner.style.color = "#111827";

  const title = document.createElement("div");
  title.id = `${BANNER_ID}-title`;
  title.style.fontWeight = "700";
  title.style.marginBottom = "4px";

  const message = document.createElement("div");
  message.id = `${BANNER_ID}-message`;

  banner.append(title, message);
  document.documentElement.appendChild(banner);
  return banner;
}

function renderBanner(payload) {
  if (!payload || payload.state === "skip") {
    const existing = document.getElementById(BANNER_ID);
    if (existing) {
      existing.remove();
    }
    return;
  }

  const banner = ensureBanner();
  const style = bannerStyles(payload.state);
  banner.style.background = style.background;
  banner.style.color = style.color;
  banner.style.borderColor = style.border;

  const title = document.getElementById(`${BANNER_ID}-title`);
  const message = document.getElementById(`${BANNER_ID}-message`);

  title.textContent = `Phishing Shield: ${style.label}`;
  message.textContent = payload.message || "No result available.";
}

chrome.runtime.onMessage.addListener((message) => {
  if (message?.type === "phishingResult") {
    renderBanner(message.payload);
  }
});

chrome.runtime.sendMessage({ type: "getCurrentAnalysis" }, (response) => {
  if (chrome.runtime.lastError) {
    return;
  }
  renderBanner(response);
});
