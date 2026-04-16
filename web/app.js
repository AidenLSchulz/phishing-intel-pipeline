/*
app.js

PURPOSE:
    Handles frontend interaction and sends requests to backend.

FLOW OVERVIEW:
    User enters domain
        -> clicks "Analyze"
        -> JS sends POST request to main.py
        -> receives result
        -> updates UI

IMPORTANT:
    - This ONLY talks to ONE endpoint: /analyze-domain
    - Does NOT call helper modules directly
*/

const analyzeBtn = document.getElementById("analyzeBtn");
const domainInput = document.getElementById("domainInput");
const resultDiv = document.getElementById("result");

// 🔧 Backend API location
const API_BASE = "http://127.0.0.1:8000";

// Attach click event
analyzeBtn.addEventListener("click", analyzeDomain);

async function analyzeDomain() {
  // STEP 1: Get user input
  const domain = domainInput.value.trim();

  // Validate input
  if (!domain) {
    resultDiv.innerHTML = "<p>Please enter a domain.</p>";
    return;
  }

  // Show loading state
  resultDiv.innerHTML = "<p>Analyzing...</p>";

  try {
    // STEP 2: Send request to backend (main.py)
    const response = await fetch(`${API_BASE}/analyze-domain`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({ domain })
    });

    // Handle server errors
    if (!response.ok) {
      throw new Error(`Server responded with ${response.status}`);
    }

    // STEP 3: Parse response
    const data = await response.json();

    // Safely extract values
    const riskScore = data.risk_score ?? 0;
    const reasons = Array.isArray(data.reasons) ? data.reasons : [];

    // Determine color/style based on score
    const scoreClass = getScoreClass(riskScore);

    // Build reasons list
    const reasonsHtml = reasons.length
      ? `<ul>${reasons.map(reason => `<li>${reason}</li>`).join("")}</ul>`
      : "<p>No suspicious indicators found.</p>";

    // STEP 4: Update UI
    resultDiv.innerHTML = `
      <p><strong>Domain:</strong> ${data.domain}</p>
      <p><strong>Risk Score:</strong> <span class="${scoreClass}">${riskScore}</span></p>
      <h3>Reasons</h3>
      ${reasonsHtml}
    `;

  } catch (error) {
    // Handle network / runtime errors
    resultDiv.innerHTML = `<p style="color:red;">Error: ${error.message}</p>`;
    console.error("Fetch error:", error);
  }
}

// Helper function for styling score
function getScoreClass(score) {
  if (score >= 40) return "score-high";
  if (score >= 20) return "score-medium";
  return "score-low";
}