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

    const score = data.risk_score;
    const scoreClass = getScoreClass(score);
    const riskLevel = data.risk_level || getRiskLevel(score);
    const badgeClass = getBadgeClass(score);

    const notesHtml = data.notes && data.notes.length
      ? `<ul class="reasons-list">${data.notes.map(note => `<li>${note}</li>`).join("")}</ul>`
      : '<p class="safe-message">Helper scores were collected successfully.</p>';

    resultDiv.innerHTML = `
      <div class="result-box">
        <div class="result-row">
          <span class="result-label">Domain Analyzed:</span> ${data.domain}
        </div>

        <div class="result-row">
          <span class="result-label">Risk Score:</span>
          <span class="${scoreClass}">${score} / 1000</span>
        </div>

        <div class="result-row">
          <span class="result-label">Risk Level:</span>
          <span class="risk-badge ${badgeClass}">${riskLevel}</span>
        </div>

        <div class="result-row">
          <span class="result-label">Findings:</span>
          ${notesHtml}
        </div>
      </div>
    `;
  } catch (error) {
    resultDiv.innerHTML = `<p class="error-message">Error: ${error.message}</p>`;
    console.error(error);
  }
}

function getScoreClass(score) {
  if (score >= 750) return "score-high";
  if (score >= 500) return "score-likely";
  if (score >= 250) return "score-medium";
  return "score-low";
}

function getRiskLevel(score) {
  if (score >= 750) return "High Risk";
  if (score >= 500) return "Likely Phishing";
  if (score >= 250) return "Suspicious";
  return "Safe";
}

function getBadgeClass(score) {
  if (score >= 750) return "badge-high";
  if (score >= 500) return "badge-likely";
  if (score >= 250) return "badge-medium";
  return "badge-low";
}