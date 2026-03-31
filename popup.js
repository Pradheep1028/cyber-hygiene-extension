// popup.js - Safe Surf Dashboard

// Helper: calculate % for metrics
function getPercent(metric) {
  if (!metric || metric.total === 0) return 100;
  const bad = metric.bad || metric.blocked || 0;
  return Math.max(0, 100 - Math.round((bad / metric.total) * 100));
}

// Helper: decide bar color
function getBarColor(val) {
  if (val >= 80) return "green";
  if (val >= 50) return "yellow";
  return "red";
}

// Draw circular gauge on canvas
function drawGauge(score) {
  const canvas = document.getElementById("scoreChart");
  const ctx = canvas.getContext("2d");
  const centerX = canvas.width / 2;
  const centerY = canvas.height / 2;
  const radius = 50;

  // Clear canvas
  ctx.clearRect(0, 0, canvas.width, canvas.height);

  // Background circle
  ctx.beginPath();
  ctx.arc(centerX, centerY, radius, 0, 2 * Math.PI);
  ctx.strokeStyle = "#ecf0f1";
  ctx.lineWidth = 10;
  ctx.stroke();

  // Progress arc
  const endAngle = (score / 100) * 2 * Math.PI - 0.5 * Math.PI;
  ctx.beginPath();
  ctx.arc(centerX, centerY, radius, -0.5 * Math.PI, endAngle);
  ctx.strokeStyle = score >= 80 ? "#2ecc71" : score >= 50 ? "#f1c40f" : "#e74c3c";
  ctx.lineWidth = 10;
  ctx.stroke();
}

function render() {
  chrome.storage.local.get(["hygieneScore", "metrics", "alerts"], (data) => {
    let score = data.hygieneScore ?? 100;
    let metrics = data.metrics || {
      password: { total: 0, bad: 0 },
      domain: { total: 0, bad: 0 },
      cookie: { total: 0, blocked: 0 },
      zfa: { total: 0, good: 0 },
      phishing: { total: 0, bad: 0 }
    };

    // ---- Gauge ----
    drawGauge(score);
    document.getElementById("scoreValue").textContent = `${score} / 100`;
    document.getElementById("scoreStatus").textContent =
      score >= 80 ? "Good" : score >= 50 ? "Needs Improvement" : "Poor";

    // ---- Metrics ----
    function setMetric(id, val) {
      document.getElementById(id).textContent = `${val}%`;
      const bar = document.getElementById(id + "Bar");
      bar.style.width = val + "%";
      bar.className = "progress " + getBarColor(val);
    }

    setMetric("pHealth", getPercent(metrics.password));
    setMetric("dSafety", getPercent(metrics.domain));
    setMetric("cControl", getPercent(metrics.cookie));
    setMetric(
      "zfa",
      metrics.zfa.total > 0 ? Math.round((metrics.zfa.good / metrics.zfa.total) * 100) : 50
    );
    setMetric("phish", getPercent(metrics.phishing));

    // ---- Alerts ----
    const alertsBox = document.getElementById("alertsList");
    alertsBox.innerHTML = "";
    if (data.alerts && data.alerts.length > 0) {
      data.alerts.slice(-5).reverse().forEach((alert) => {
        const div = document.createElement("div");
        div.className = "alert-item";
        div.textContent = alert;
        alertsBox.appendChild(div);
      });
    } else {
      alertsBox.innerHTML = "<div class='alert-item'>✅ No recent alerts</div>";
    }
  });
}

// Reset button handler
document.getElementById("reset").addEventListener("click", () => {
  chrome.storage.local.set(
    {
      hygieneScore: 100,
      alerts: [],
      phishCache: {},
      metrics: {
        password: { total: 0, bad: 0 },
        domain: { total: 0, bad: 0 },
        cookie: { total: 0, blocked: 0 },
        zfa: { total: 0, good: 0 },
        phishing: { total: 0, bad: 0 }
      }
    },
    render
  );
});

// Run when popup opens
document.addEventListener("DOMContentLoaded", render);

// Live updates whenever background changes storage
chrome.storage.onChanged.addListener((changes, area) => {
  if (area === "local") render();
});
// ================= AI CHAT =================

const chatBox = document.getElementById("chatBox");
const sendBtn = document.getElementById("sendAI");
const input = document.getElementById("aiQuestion");

if (sendBtn) {
  sendBtn.addEventListener("click", sendToAI);
}

function sendToAI() {

  const question = input.value.trim();
  if (!question) return;

  addChat("You", question);

  input.value = "";

  callAI(question);
}

// Show messages
function addChat(sender, text) {

  const p = document.createElement("p");

  p.innerHTML = `<b>${sender}:</b> ${text}`;

  chatBox.appendChild(p);

  chatBox.scrollTop = chatBox.scrollHeight;
}

// Call backend AI
async function callAI(question) {

  // Fallback values (avoid crash)
  const context = {
    url: window.location?.href || "unknown",
    score: window.currentScore || 0,
    reasons: window.currentReasons || []
  };

  try {

    const res = await fetch("http://localhost:5000/askAI", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        question,
        context
      })
    });

    const data = await res.json();

    if (data.answer) {
      addChat("AI", data.answer);
    } else {
      addChat("AI", "No response from AI.");
    }

  } catch (e) {

    console.error(e);
    addChat("AI", "Error connecting to AI server.");

  }
}

// ================= XAI =================

function loadXAI() {

  const list = document.getElementById("xaiList");

  if (!list) return;

  list.innerHTML = "";

  const reasons = window.currentReasons || [
    "HTTPS Enabled",
    "Trusted Domain",
    "Low 2FA Usage"
  ];

  reasons.forEach(r => {
    const li = document.createElement("li");
    li.textContent = r;
    list.appendChild(li);
  });
}

// Load XAI after page loads
document.addEventListener("DOMContentLoaded", loadXAI);
















