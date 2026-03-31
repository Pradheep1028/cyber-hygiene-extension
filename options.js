// Load saved settings
document.addEventListener("DOMContentLoaded", () => {
  chrome.storage.local.get([
    "backendUrl", "phishApi", "phishThreshold", "penalties", "modules"
  ], (data) => {
    document.getElementById("backendUrl").value = data.backendUrl || "http://localhost:5000/checkURL";
    document.getElementById("phishApi").value = data.phishApi || "http://localhost:5001/predictPhish";
    document.getElementById("phishThreshold").value = data.phishThreshold ?? 0.7;

    const penalties = data.penalties || { password: 15, phishing: 10, unsafe: 20 };
    document.getElementById("penaltyPassword").value = penalties.password;
    document.getElementById("penaltyPhishing").value = penalties.phishing;
    document.getElementById("penaltyUnsafe").value = penalties.unsafe;

    const modules = data.modules || { password: true, phishing: true, cookies: true, domain: true };
    document.getElementById("modPassword").checked = modules.password;
    document.getElementById("modPhishing").checked = modules.phishing;
    document.getElementById("modCookies").checked = modules.cookies;
    document.getElementById("modDomain").checked = modules.domain;
  });
});

// Save settings
document.getElementById("saveBtn").addEventListener("click", () => {
  const backendUrl = document.getElementById("backendUrl").value;
  const phishApi = document.getElementById("phishApi").value;
  const phishThreshold = parseFloat(document.getElementById("phishThreshold").value);

  const penalties = {
    password: parseInt(document.getElementById("penaltyPassword").value, 10),
    phishing: parseInt(document.getElementById("penaltyPhishing").value, 10),
    unsafe: parseInt(document.getElementById("penaltyUnsafe").value, 10)
  };

  const modules = {
    password: document.getElementById("modPassword").checked,
    phishing: document.getElementById("modPhishing").checked,
    cookies: document.getElementById("modCookies").checked,
    domain: document.getElementById("modDomain").checked
  };

  chrome.storage.local.set({ backendUrl, phishApi, phishThreshold, penalties, modules }, () => {
    document.getElementById("status").textContent = "✅ Settings saved!";
    setTimeout(() => { document.getElementById("status").textContent = ""; }, 2000);
  });
});

