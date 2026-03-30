const analyzeBtn = document.getElementById("analyzeBtn");
const domainInput = document.getElementById("domainInput");
const resultDiv = document.getElementById("result");

// 🔧 CHANGE THIS PORT if needed
const API_BASE = "http://127.0.0.1:8000"; // or 8010 if you're using that

analyzeBtn.addEventListener("click", analyzeDomain);

async function analyzeDomain() {
  const domain = domainInput.value.trim();

  if (!domain) {
    resultDiv.innerHTML = "<p>Please enter a domain.</p>";
    return;
  }

  resultDiv.innerHTML = "<p>Analyzing...</p>";

  try {
    const response = await fetch(`${API_BASE}/analyze-domain`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ domain })
    });

    // 🚨 IMPORTANT: catch bad responses
    if (!response.ok) {
      throw new Error(`Server responded with ${response.status}`);
    }

    const data = await response.json();

    const scoreClass = getScoreClass(data.risk_score);

    const reasonsHtml = data.reasons.length
      ? `<ul>${data.reasons.map(reason => `<li>${reason}</li>`).join("")}</ul>`
      : "<p>No suspicious indicators found.</p>";

    resultDiv.innerHTML = `
      <p><strong>Domain:</strong> ${data.domain}</p>
      <p><strong>Risk Score:</strong> <span class="${scoreClass}">${data.risk_score}</span></p>
      <h3>Reasons</h3>
      ${reasonsHtml}
    `;
  } catch (error) {
    resultDiv.innerHTML = `<p style="color:red;">Error: ${error.message}</p>`;
    console.error("Fetch error:", error);
  }
}

function getScoreClass(score) {
  if (score >= 40) return "score-high";
  if (score >= 20) return "score-medium";
  return "score-low";
}