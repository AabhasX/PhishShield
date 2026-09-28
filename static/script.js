/**
 * PhishShield — Client-Side Logic & Telemetry
 * Monochromatic Vercel/Linear Minimalist Interface
 */

let lastAnalysisResult = null;

// Populate sample URL and initiate scan
function setSample(url) {
  const input = document.getElementById("urlInput");
  input.value = url;
  input.focus();
  scanUrl();
}

// Perform URL Scan via API
async function scanUrl() {
  const input = document.getElementById("urlInput");
  const button = document.getElementById("scanBtn");
  const btnText = button.querySelector(".btn-text");
  const errorBox = document.getElementById("errorBox");
  const section = document.getElementById("resultSection");
  const url = input.value.trim();

  errorBox.classList.add("hidden");
  errorBox.textContent = "";

  if (!url) {
    errorBox.textContent = "Please enter a valid URL to inspect.";
    errorBox.classList.remove("hidden");
    input.focus();
    return;
  }

  // Loading state
  button.disabled = true;
  if (btnText) btnText.textContent = "Scanning...";

  try {
    // Primary endpoint /api/scan with fallback to /analyze
    let response;
    try {
      response = await fetch("/api/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
      if (!response.ok && response.status === 404) {
        response = await fetch("/analyze", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url })
        });
      }
    } catch {
      response = await fetch("/analyze", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url })
      });
    }

    const data = await response.json();
    if (!response.ok) {
      throw new Error(data.error || "Analysis failed. Please check the URL.");
    }

    lastAnalysisResult = data;
    renderResult(data);
    await loadDashboard();
  } catch (error) {
    errorBox.textContent = error.message;
    errorBox.classList.remove("hidden");
    section.classList.add("hidden");
  } finally {
    button.disabled = false;
    if (btnText) btnText.textContent = "Scan URL";
  }
}

// Render Analysis Report
function renderResult(data) {
  const section = document.getElementById("resultSection");
  section.classList.remove("hidden");

  // Status & URLs
  const statusEl = document.getElementById("resultStatus");
  statusEl.textContent = data.status;

  const urlEl = document.getElementById("resultUrl");
  urlEl.textContent = data.url;

  const hostEl = document.getElementById("hostValue");
  hostEl.textContent = data.host || "Unable to parse domain";

  const scoreEl = document.getElementById("scoreValue");
  scoreEl.textContent = data.score;

  // Status Badge styling
  const badge = document.getElementById("resultBadge");
  badge.className = "status-pill";
  if (data.status === "SAFE") {
    badge.classList.add("safe");
  } else if (data.status === "SUSPICIOUS") {
    badge.classList.add("suspicious");
  } else {
    badge.classList.add("high");
  }

  // Triggered Indicators List
  const list = document.getElementById("reasonsList");
  list.innerHTML = "";

  const reasons = data.reasons || [];
  const countEl = document.getElementById("reasonsCount");
  if (countEl) {
    countEl.textContent = `${reasons.length} ${reasons.length === 1 ? 'indicator' : 'indicators'}`;
  }

  reasons.forEach(reason => {
    const item = document.createElement("div");
    item.className = "reason-item";

    const bullet = document.createElement("span");
    bullet.className = "reason-bullet";

    const text = document.createElement("span");
    text.textContent = reason;

    item.appendChild(bullet);
    item.appendChild(text);
    list.appendChild(item);
  });

  // Smooth scroll into view
  section.scrollIntoView({
    behavior: "smooth",
    block: "nearest"
  });
}

// Copy Summary Action
async function copySummary() {
  if (!lastAnalysisResult) return;

  const res = lastAnalysisResult;
  const reasonsText = (res.reasons || []).map(r => ` • ${r}`).join("\n");
  const summary = [
    `=== PhishShield Analysis Report ===`,
    `Target URL:   ${res.url}`,
    `Domain Host:  ${res.host}`,
    `Risk Score:   ${res.score}/100`,
    `Threat Level: ${res.status}`,
    `Indicators:`,
    reasonsText
  ].join("\n");

  const btn = document.getElementById("copySummaryBtn");
  const textEl = document.getElementById("copyBtnText");

  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(summary);
    } else {
      // Fallback for non-https / older contexts
      const textarea = document.createElement("textarea");
      textarea.value = summary;
      textarea.style.position = "fixed";
      textarea.style.left = "-9999px";
      document.body.appendChild(textarea);
      textarea.select();
      document.execCommand("copy");
      document.body.removeChild(textarea);
    }

    if (textEl) textEl.textContent = "Copied!";
    btn.style.borderColor = "#22c55e";
    btn.style.color = "#22c55e";

    setTimeout(() => {
      if (textEl) textEl.textContent = "Copy Summary";
      btn.style.borderColor = "";
      btn.style.color = "";
    }, 2000);
  } catch (err) {
    console.error("Failed to copy report:", err);
  }
}

// Load Telemetry Dashboard & Scan History
async function loadDashboard() {
  try {
    // Attempt /api/stats and /api/history first with fallback to /stats and /history
    const fetchStats = async () => {
      let r = await fetch("/api/stats");
      if (!r.ok && r.status === 404) r = await fetch("/stats");
      return r.json();
    };

    const fetchHistory = async () => {
      let r = await fetch("/api/history");
      if (!r.ok && r.status === 404) r = await fetch("/history");
      return r.json();
    };

    const [stats, history] = await Promise.all([fetchStats(), fetchHistory()]);

    // Update Telemetry Counters
    document.getElementById("totalStat").textContent = stats.total ?? 0;
    document.getElementById("safeStat").textContent = stats.safe ?? 0;
    document.getElementById("suspiciousStat").textContent = stats.suspicious ?? 0;
    document.getElementById("highRiskStat").textContent = stats.high_risk ?? 0;

    // Render History Table
    const body = document.getElementById("historyBody");
    if (!history || !history.length) {
      body.innerHTML = `
        <tr>
          <td colspan="4" class="empty-state">
            <div class="empty-wrap">
              <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round">
                <circle cx="12" cy="12" r="10"></circle>
                <line x1="8" y1="12" x2="16" y2="12"></line>
              </svg>
              <span>No scan entries recorded yet. Enter a URL above to start.</span>
            </div>
          </td>
        </tr>`;
      return;
    }

    body.innerHTML = history.map(row => {
      const statusClass = row.status === "SAFE" ? "safe" :
                          row.status === "SUSPICIOUS" ? "suspicious" : "high";
      return `<tr>
        <td class="td-url" title="${escapeHtml(row.url)}">${escapeHtml(row.url)}</td>
        <td class="td-score">${row.score} / 100</td>
        <td>
          <span class="tag-status ${statusClass}">
            <span class="status-dot"></span>
            ${escapeHtml(row.status)}
          </span>
        </td>
        <td class="td-time">${escapeHtml(row.scanned_at)}</td>
      </tr>`;
    }).join("");

  } catch (err) {
    console.error("Failed to load dashboard telemetry:", err);
  }
}

// Security HTML escaping
function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

// Enter Key listener for input
document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("urlInput");
  if (input) {
    input.addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        scanUrl();
      }
    });
  }

  // Initial dashboard telemetry load
  loadDashboard();
});
