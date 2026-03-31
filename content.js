// content.js - combined: password checks + phishing feature extraction + banner UI

/* ---------------- Config ---------------- */
const HIBP_DEBOUNCE_MS = 3000; // wait before checking HIBP after typing stops
const PHISH_FEATURE_CACHE_MS = 30 * 60 * 1000; // 30 minutes

/* ---------------- Password hygiene (weak + HIBP) ---------------- */
let hibpTimer = null;
let hibpAbort = null;
let lastCheckedPasswordHash = null;

function isWeakPassword(password) {
  const common = ["123456", "password", "qwerty", "111111", "abc123"];
  return password.length < 8 || common.includes(password.toLowerCase());
}

async function sha1(str) {
  const buffer = new TextEncoder().encode(str);
  const hashBuffer = await crypto.subtle.digest("SHA-1", buffer);
  return Array.from(new Uint8Array(hashBuffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

async function checkPwnedPassword(password) {
  try {
    const hash = await sha1(password);
    if (hash === lastCheckedPasswordHash) return;
    lastCheckedPasswordHash = hash;

    const prefix = hash.slice(0, 5);
    const suffix = hash.slice(5);

    // Abort previous HIBP request if any
    if (hibpAbort) {
      try { hibpAbort.abort(); } catch (e) {}
      hibpAbort = null;
    }
    hibpAbort = new AbortController();

    const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, { signal: hibpAbort.signal });
    if (!res.ok) return;
    const text = await res.text();
    if (text.includes(suffix)) {
      chrome.runtime.sendMessage({
        type: "PASSWORD_ALERT",
        message: "⚠ This password has been found in data breaches!"
      });
    }
  } catch (err) {
    if (err.name === 'AbortError') {
      // expected when we cancel previous request
      return;
    }
    console.error("HIBP check error:", err);
  } finally {
    hibpAbort = null;
  }
}

function onPasswordInput(e) {
  try {
    const pwd = e.target.value || "";
    if (pwd.length === 0) return;

    if (isWeakPassword(pwd)) {
      chrome.runtime.sendMessage({
        type: "PASSWORD_ALERT",
        message: "⚠ Weak or common password detected!"
      });
    }

    // debounce HIBP checks
    if (hibpTimer) clearTimeout(hibpTimer);
    if (pwd.length >= 8) {
      hibpTimer = setTimeout(() => checkPwnedPassword(pwd), HIBP_DEBOUNCE_MS);
    }
  } catch (err) {
    console.error("password input handler error:", err);
  }
}

/* ---------------- Phishing feature extraction & quick heuristic ---------------- */

function isIPAddress(host) {
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
}
function countSubdomains(host) {
  const parts = host.split('.').filter(Boolean);
  return Math.max(0, parts.length - 2);
}
function hasPunycode(host) {
  return host.includes('xn--');
}
function suspiciousTokensIn(url) {
  const tokens = ['login','secure','account','update','verify','signin','bank','confirm','password','verify-account','secure-login'];
  const lower = url.toLowerCase();
  return tokens.reduce((acc,t)=> acc + (lower.includes(t) ? 1 : 0), 0);
}

function extractModelFeatures() {
  try {
    const u = new URL(location.href);
    const host = u.hostname || '';
    return {
      host: host,
      url_length: location.href.length,
      host_length: host.length,
      path_length: u.pathname.length,
      query_length: u.search.length,
      subdomain_count: countSubdomains(host),
      contains_ip: isIPAddress(host) ? 1 : 0,
      has_at: location.href.includes('@') ? 1 : 0,
      has_punycode: hasPunycode(host) ? 1 : 0,
      suspicious_token_count: suspiciousTokensIn(location.href),
      is_https: location.protocol === 'https:' ? 1 : 0
    };
  } catch (err) {
    console.error("extractModelFeatures error:", err);
    return {};
  }
}

function sendPhishFeaturesIfNeeded() {
  const features = extractModelFeatures();
  const host = features.host || 'unknown';
  try {
    chrome.storage.local.get(['phishCache'], (st) => {
      const cache = st.phishCache || {};
      const now = Date.now();
      const entry = cache[host];
      if (entry && (now - entry.ts) < PHISH_FEATURE_CACHE_MS) {
        chrome.runtime.sendMessage({ type: 'PHISH_RESULT', score: entry.score, reasons: entry.reasons || [] });
        return;
      }
      chrome.runtime.sendMessage({ type: 'PHISH_FEATURES', features });
    });
  } catch (err) {
    console.error("phish feature send error:", err);
  }
}

function quickHeuristicScore(f) {
  let s = 0;
  if (f.contains_ip) s += 0.25;
  if (f.has_punycode) s += 0.20;
  if (f.has_at) s += 0.15;
  if (f.subdomain_count >= 4) s += 0.15;
  if (f.suspicious_token_count >= 2) s += 0.15;
  if (f.is_https === 0) s += 0.05;
  return Math.max(0, Math.min(1, s));
}

/* ---------------- UI: simple banner for warnings ---------------- */

function injectBanner({ id = 'safe-surf-phish-banner', level = 'warn', title = '', details = '', actions = [] }) {
  try {
    if (document.getElementById(id)) return;
    const wrap = document.createElement('div');
    wrap.id = id;
    const bg = level === 'danger' ? '#ffdddd' : '#fff4cc';
    wrap.style.cssText = `
      position: fixed; top: 0; left: 0; right: 0; z-index: 2147483647;
      font-family: system-ui, -apple-system, "Segoe UI", Roboto, "Helvetica Neue", Arial;
      padding: 10px 14px; display:flex; gap:12px; align-items:center;
      border-bottom:1px solid rgba(0,0,0,.08); box-shadow:0 2px 6px rgba(0,0,0,.06);
      background:${bg}; color:#111;
    `;
    const titleEl = document.createElement('strong');
    titleEl.textContent = title;
    titleEl.style.marginRight = '8px';
    const detailsEl = document.createElement('span');
    detailsEl.textContent = details;
    wrap.appendChild(titleEl);
    wrap.appendChild(detailsEl);
    const spacer = document.createElement('div'); spacer.style.flex = '1';
    wrap.appendChild(spacer);
    actions.forEach(a => {
      const btn = document.createElement('button');
      btn.textContent = a.label;
      btn.style.cssText = 'padding:6px 10px;border-radius:6px;border:1px solid rgba(0,0,0,.08);cursor:pointer;background:#fff;margin-left:8px';
      btn.addEventListener('click', a.onClick);
      wrap.appendChild(btn);
    });
    document.documentElement.appendChild(wrap);
  } catch (err) {
    console.error("injectBanner error:", err);
  }
}

function removeBanner() {
  const el = document.getElementById('safe-surf-phish-banner');
  if (el) el.remove();
}

/* ---------------- React to PHISH_RESULT from background ---------------- */
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  try {
    if (msg && msg.type === 'PHISH_RESULT') {
      const score = msg.score || 0;
      const reasons = msg.reasons || [];
      removeBanner();
      if (score >= 0.7) {
        injectBanner({
          level: 'danger',
          title: 'Safe Surf — Potential phishing detected',
          details: `Risk ${Math.round(score * 100)}%. ${reasons.join(', ')}`,
          actions: [
            { label: 'Go Back', onClick: () => { try { if (history.length) history.back(); else window.close(); } catch(e){ window.location.href = 'about:blank'; } } },
            { label: 'Proceed Anyway', onClick: () => removeBanner() }
          ]
        });
      } else if (score >= 0.5) {
        injectBanner({
          level: 'warn',
          title: 'Safe Surf — Suspicious site',
          details: `Risk ${Math.round(score * 100)}%.`,
          actions: [{ label: 'Dismiss', onClick: () => removeBanner() }]
        });
      } else {
        // low risk — no banner
      }
    }
  } catch (e) {
    console.error("PHISH_RESULT handler error:", e);
  }
});

/* ---------------- Run checks on page load ---------------- */
(function init() {
  try {
    const features = extractModelFeatures();
    const quick = quickHeuristicScore(features);
    if (quick >= 0.6) {
      injectBanner({
        level: 'warn',
        title: 'Safe Surf — Suspicious site (heuristic)',
        details: 'We are running a deeper check…',
        actions: [{ label: 'Dismiss', onClick: () => removeBanner() }]
      });
    }
    sendPhishFeaturesIfNeeded();
  } catch (err) {
    console.error("initial phish check error:", err);
  }

  // Attach password listener globally (captures dynamically inserted fields)
  document.addEventListener("input", (e) => {
    try {
      if (e.target && e.target.type === "password") onPasswordInput(e);
    } catch (err) {
      console.error("password input handler error:", err);
    }
  });

  // Remove banner on navigation/unload to avoid stale UI
  window.addEventListener('beforeunload', removeBanner);
  document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') removeBanner(); });
})();



