const analyzeBtn = document.getElementById("analyzeBtn");
const domainInput = document.getElementById("domainInput");
const resultDiv = document.getElementById("result");
const loadSummaryBtn = document.getElementById("loadSummaryBtn");
const summaryResultDiv = document.getElementById("summaryResult");
const loadIndicatorReportBtn = document.getElementById("loadIndicatorReportBtn");

const API_BASE = "http://127.0.0.1:8000";

analyzeBtn.addEventListener("click", analyzeDomain);
loadSummaryBtn.addEventListener("click", loadResultsSummary);
loadIndicatorReportBtn.addEventListener("click", loadIndicatorReport);

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

// ✅ NEW
async function loadResultsSummary() {
  summaryResultDiv.innerHTML = `
    <div class="empty-state">
      <p>Loading summary...</p>
      <span>Reading saved scan results from the database.</span>
    </div>
  `;

  try {
    const response = await fetch(`${API_BASE}/results-summary`);

    if (!response.ok) {
      throw new Error(`Server responded with ${response.status}`);
    }

    const data = await response.json();

    const riskBreakdownHtml = data.risk_breakdown.length
      ? data.risk_breakdown.map(item => `
          <li>${item.risk_level}: ${item.count}</li>
        `).join("")
      : "<li>No risk breakdown available.</li>";

    const latestScansHtml = data.latest_scans.length
      ? data.latest_scans.map(scan => `
          <tr>
            <td>${scan.domain}</td>
            <td>${scan.final_score}</td>
            <td>${scan.risk_level}</td>
            <td>${scan.timestamp}</td>
          </tr>
        `).join("")
      : `
          <tr>
            <td colspan="4">No scans found.</td>
          </tr>
        `;

    summaryResultDiv.innerHTML = `
      <div class="result-box">
        <div class="result-row">
          <span class="result-label">Total Saved Scans:</span> ${data.total_scans}
        </div>

        <div class="result-row">
          <span class="result-label">Risk Breakdown:</span>
          <ul class="reasons-list">
            ${riskBreakdownHtml}
          </ul>
        </div>

        <div class="result-row">
          <span class="result-label">Latest 10 Scans:</span>
          <table class="summary-table">
            <thead>
              <tr>
                <th>Domain</th>
                <th>Score</th>
                <th>Risk</th>
                <th>Timestamp</th>
              </tr>
            </thead>
            <tbody>
              ${latestScansHtml}
            </tbody>
          </table>
        </div>
      </div>
    `;
  } catch (error) {
    summaryResultDiv.innerHTML = `<p class="error-message">Error: ${error.message}</p>`;
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

async function loadIndicatorReport() {
  const container = document.getElementById("indicatorReport");

  container.innerHTML = `
    <div class="empty-state">
      <p>Loading indicator report...</p>
      <span>Analyzing indicator trends.</span>
    </div>
  `;

  try {
    const response = await fetch(`${API_BASE}/reports/indicators`);

    if (!response.ok) {
      throw new Error(`Server responded with ${response.status}`);
    }

    const report = await response.json();

    if (!report.length) {
      container.innerHTML = "<p>No indicator data found.</p>";
      return;
    }

    container.innerHTML = "";

    report.forEach(indicator => {
      const section = document.createElement("div");
      section.className = "indicator-card";

      section.innerHTML = `
        <button class="indicator-header">
          <span>${indicator.indicator_name}</span>
          <span>${indicator.hit_count} hits</span>
        </button>

        <div class="indicator-details">
          <table>
            <thead>
              <tr>
                <th>Domain</th>
                <th>Details</th>
                <th>Score</th>
                <th>Risk</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              ${indicator.top_domains.map(d => `
                <tr>
                  <td>${d.domain}</td>
                  <td>${d.details}</td>
                  <td>${d.risk_score}</td>
                  <td>${d.risk_level}</td>
                  <td>${d.scanned_at}</td>
                </tr>
              `).join("")}
            </tbody>
          </table>
        </div>
      `;

      const header = section.querySelector(".indicator-header");
      const details = section.querySelector(".indicator-details");

      details.style.display = "none";

      header.addEventListener("click", () => {
        details.style.display =
          details.style.display === "none" ? "block" : "none";
      });

      container.appendChild(section);
    });

  } catch (error) {
    container.innerHTML = `<p class="error-message">Error: ${error.message}</p>`;
    console.error(error);
  }
}