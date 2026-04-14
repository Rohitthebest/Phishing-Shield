const form = document.getElementById("detector-form");
const input = document.getElementById("url-input");
const resultCard = document.getElementById("result-card");
const errorText = document.getElementById("error-text");
const riskLevel = document.getElementById("risk-level");
const verdictBadge = document.getElementById("verdict-badge");
const scoreValue = document.getElementById("score-value");
const summaryText = document.getElementById("summary-text");

for (const button of document.querySelectorAll(".sample-link")) {
  button.addEventListener("click", () => {
    input.value = button.dataset.url;
    form.requestSubmit();
  });
}

form.addEventListener("submit", async (event) => {
  event.preventDefault();

  const url = input.value.trim();
  if (!url) {
    showError("Please enter a URL to analyze.");
    return;
  }

  hideError();
  resultCard.classList.add("hidden");

  try {
    const response = await fetchPrediction("/predict", url);
    const data = await response.json();
    if (!response.ok) {
      showError(data.error || "Something went wrong during analysis.");
      return;
    }

    renderResult(data);
  } catch (error) {
    showError("The detector could not reach the server. Try again in a moment.");
  }
});

async function fetchPrediction(endpoint, url, signal) {
  return fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ url }),
    signal,
  });
}

function renderResult(data) {
  const stateClass = `status-${data.risk_level.toLowerCase()}`;
  resultCard.className = `result-card ${stateClass}`;
  resultCard.style.setProperty(
    "--score-angle",
    `${Math.round((data.phishing_probability / 100) * 360)}deg`
  );

  if (!data.valid_url) {
    riskLevel.textContent = "Invalid URL";
    verdictBadge.textContent = "Fix format";
    verdictBadge.className = "verdict-badge verdict-invalid";
    scoreValue.textContent = "--";
    summaryText.textContent =
      "This is not a valid website URL. Please enter a correct URL.";
  } else {
    riskLevel.textContent = data.is_phishing ? "Phishing" : "Safe";
    verdictBadge.textContent = data.verdict;
    verdictBadge.className = `verdict-badge ${
      data.is_phishing ? "verdict-phishing" : "verdict-safe"
    }`;
    scoreValue.textContent = `${Math.round(data.phishing_probability)}%`;
    summaryText.textContent = data.is_phishing
      ? "This website looks like phishing."
      : "This website looks safe.";
  }

  resultCard.classList.remove("hidden");
}

function showError(message) {
  errorText.textContent = message;
  errorText.classList.remove("hidden");
}

function hideError() {
  errorText.textContent = "";
  errorText.classList.add("hidden");
}
