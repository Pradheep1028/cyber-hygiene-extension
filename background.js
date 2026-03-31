// background.js - Safe Surf consolidated background service worker
// Handles: Safe Browsing checks, password alerts, phishing ML API requests,
// caching, notifications, storage updates, and metrics for dashboard.

// CONFIG (single backend server)
const SAFE_BROWSING_BACKEND = "http://localhost:5000/checkURL";
const PHISHING_ML_API = "http://127.0.0.1:5001/predictPhish";

const PHISH_CACHE_TTL = 30 * 60 * 1000; // 30 minutes
const PHISH_THRESHOLD = 0.7;            // score >= → phishing
const UNSAFE_SITE_PENALTY = -20;
const PASSWORD_PENALTY = -15;
const PHISH_PENALTY = -10;

// ------ Utility helpers ------
function safeLog(...args) {
  try { console.log("[SafeSurf]", ...args); } catch (e) {}
}

function setStorage(updates) {
  safeLog("📝 setStorage", updates);
  return new Promise((resolve) => chrome.storage.local.set(updates, resolve));
}
function getStorage(keys) {
  return new Promise((resolve) => chrome.storage.local.get(keys, resolve));
}

// Add alert into storage
async function pushAlert(text) {
  const stored = await getStorage(["alerts", "hygieneScore"]);
  const alerts = stored.alerts || [];
  alerts.push(text);
  const score = stored.hygieneScore != null ? stored.hygieneScore : 100;
  safeLog("⚠️ pushAlert:", text);
  await setStorage({ alerts, hygieneScore: score });
}

// Update hygiene score
async function changeScore(delta, reasonText) {
  const stored = await getStorage(["hygieneScore", "alerts"]);
  let score = stored.hygieneScore != null ? stored.hygieneScore : 100;
  score = Math.max(0, Math.min(100, score + delta));
  const alerts = stored.alerts || [];
  if (reasonText) alerts.push(reasonText);
  safeLog("📉 changeScore:", delta, "→", score, "reason:", reasonText);
  await setStorage({ hygieneScore: score, alerts });
  return score;
}

// ------ Update Metrics ------
async function updateMetric(metric, success) {
  const stored = await getStorage(["metrics"]);
  let metrics = stored.metrics || {
    password: { total: 0, bad: 0 },
    domain: { total: 0, bad: 0 },
    cookie: { total: 0, blocked: 0 },
    zfa: { total: 0, good: 0 },
    phishing: { total: 0, bad: 0 }
  };

  if (metric === "password") {
    metrics.password.total++;
    if (!success) metrics.password.bad++;
  }
  if (metric === "domain") {
    metrics.domain.total++;
    if (!success) metrics.domain.bad++;
  }
  if (metric === "cookie") {
    metrics.cookie.total++;
    if (!success) metrics.cookie.blocked++;
  }
  if (metric === "phishing") {
    metrics.phishing.total++;
    if (!success) metrics.phishing.bad++;
  }

  safeLog("📊 updateMetric:", metric, "→", metrics[metric]);
  await setStorage({ metrics });
}

// ------ 1) Safe Browsing site check ------
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab.url || tab.url.startsWith("chrome://")) return;

  safeLog("🌐 tab updated:", tab.url);

  fetch(SAFE_BROWSING_BACKEND, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url: tab.url })
  })
    .then(r => r.json())
    .then(async data => {
      if (data && data.matches) {
        safeLog("❌ Unsafe site:", tab.url);
        await changeScore(UNSAFE_SITE_PENALTY, `⚠ Malicious site: ${tab.url}`);
        await updateMetric("domain", false);
        chrome.notifications.create({
          type: "basic",
          iconUrl: "icons/icon48.png",
          title: "Safe Surf Alert",
          message: `⚠ Malicious site detected: ${tab.url}`,
          priority: 2
        });
      } else {
        safeLog("✅ Safe site:", tab.url);
        await updateMetric("domain", true);
      }
    })
    .catch(err => safeLog("❌ Safe Browsing check error:", err));
});

// ------ 2) Messages from content.js ------
chrome.runtime.onMessage.addListener((msg, sender) => {
  try {
    if (!msg || !msg.type) return;

    // Password alert
    if (msg.type === "PASSWORD_ALERT") {
      safeLog("🔐 Password alert:", msg.message);
      changeScore(PASSWORD_PENALTY, `🔐 Password issue: ${msg.message}`)
        .then(() => {
          chrome.notifications.create({
            type: "basic",
            iconUrl: "icons/icon48.png",
            title: "Safe Surf Password Alert",
            message: msg.message,
            priority: 2
          });
        });
      updateMetric("password", false);
      return;
    }

    // Phishing features
    if (msg.type === "PHISH_FEATURES" && msg.features) {
      handlePhishFeatures(msg.features, sender);
      return;
    }
  } catch (e) {
    safeLog("❌ onMessage handler error:", e);
  }
});

// ------ 3) Phishing ML handling ------
async function handlePhishFeatures(features, sender) {
  try {
    const host = features.host || "unknown";
    const st = await getStorage(["phishCache"]);
    const cache = st.phishCache || {};
    const entry = cache[host];
    const now = Date.now();

    if (entry && (now - entry.ts) < PHISH_CACHE_TTL) {
      safeLog("📦 Using cached verdict:", host, entry.score);
      if (sender?.tab?.id != null) {
        chrome.tabs.sendMessage(sender.tab.id, { type: "PHISH_RESULT", score: entry.score, reasons: entry.reasons });
      }
      return;
    }

    const resp = await fetch(PHISHING_ML_API, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ features })
    });

    if (!resp.ok) {
      safeLog("❌ Phish API error:", resp.status);
      return;
    }

    const data = await resp.json();
    const score = typeof data.phishing_score === "number" ? data.phishing_score : 0;
    const reasons = data.reasons || [];

    cache[host] = { ts: now, score, reasons };
    await setStorage({ phishCache: cache });

    if (score >= PHISH_THRESHOLD) {
      safeLog("🚩 Phishing risk:", host, score, reasons);
      await changeScore(PHISH_PENALTY, `🚩 Phishing risk on ${host} (${Math.round(score * 100)}%)`);
      await updateMetric("phishing", false);
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon48.png",
        title: "Safe Surf: Phishing risk",
        message: `Site may be deceptive. Reasons: ${reasons.join(", ")}`,
        priority: 2
      });
    } else {
      safeLog("✅ Phishing check safe:", host, score);
      await updateMetric("phishing", true);
    }

    if (sender?.tab?.id != null) {
      chrome.tabs.sendMessage(sender.tab.id, { type: "PHISH_RESULT", score, reasons });
    }
  } catch (err) {
    safeLog("❌ handlePhishFeatures error:", err);
  }
}

// ------ 4) Initialize on install ------
chrome.runtime.onInstalled.addListener(() => {
  safeLog("🚀 Safe Surf installed - initializing storage");
  chrome.storage.local.get(["hygieneScore"], (st) => {
    if (st.hygieneScore == null) {
      chrome.storage.local.set({
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
      }, () => safeLog("✅ Initialized storage with defaults"));
    }
  });
});

