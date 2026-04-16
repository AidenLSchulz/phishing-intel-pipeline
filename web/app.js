const analyzeBtn = document.getElementById("analyzeBtn");
const domainInput = document.getElementById("domainInput");
const resultDiv = document.getElementById("result");

const API_BASE = "http://127.0.0.1:8000";

analyzeBtn.addEventListener("click", analyzeDomain);
domainInput.addEventListener("keypress", function (event) {
  if (event.key === "Enter") {
    analyzeDomain();
  }
});

async function analyzeDomain() {
  const domain = domainInput.value.trim();

  if (!domain) {
    resultDiv.innerHTML = '<p class="error-message">Please enter a domain.</p>';
    return;
  }

  resultDiv.innerHTML = `
    <div class="empty-state">
      <p>Running analysis...</p>
      <span>Please wait while the domain is evaluated.</span>
    </div>
  `;

  try {
    const response = await fetch(`${API_BASE}/analyze-domain`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ domain })
    });

    if (!response.ok) {
      throw new Error(`Server responded with ${response.status}`);
    }

    const data = await response.json();

    const scoreClass = getScoreClass(data.risk_score);
    const riskLevel = getRiskLevel(data.risk_score);
    const badgeClass = getBadgeClass(data.risk_score);

    const reasonsHtml = data.reasons && data.reasons.length
      ? `<ul class="reasons-list">${data.reasons.map(reason => `<li>${reason}</li>`).join("")}</ul>`
      : '<p class="safe-message">No suspicious indicators found. Domain appears safe.</p>';

    resultDiv.innerHTML = `
      <div class="result-box">
        <div class="result-row">
          <span class="result-label">Domain Analyzed:</span> ${data.domain}
        </div>

        <div class="result-row">
          <span class="result-label">Risk Score:</span>
          <span class="${scoreClass}">${data.risk_score}</span>
        </div>

        <div class="result-row">
          <span class="result-label">Risk Level:</span>
          <span class="risk-badge ${badgeClass}">${riskLevel}</span>
        </div>

        <div class="result-row">
          <span class="result-label">Findings:</span>
          ${reasonsHtml}
        </div>
      </div>
    `;
  } catch (error) {
    resultDiv.innerHTML = `<p class="error-message">Error: ${error.message}</p>`;
    console.error(error);
  }
}

function getScoreClass(score) {
  if (score >= 40) return "score-high";
  if (score >= 20) return "score-medium";
  return "score-low";
}

function getRiskLevel(score) {
  if (score >= 40) return "High";
  if (score >= 20) return "Medium";
  return "Low";
}

function getBadgeClass(score) {
  if (score >= 40) return "badge-high";
  if (score >= 20) return "badge-medium";
  return "badge-low";
}