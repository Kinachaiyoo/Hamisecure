console.log("Hamisecure UI v7 loaded");

const KEY = "hamisecure_history";
let LAST_JSON = null;

function fmt(n){ return (typeof n === "number") ? n.toFixed(3) : String(n); }

function setRisk(prob, pred){
  const pct = Math.max(0, Math.min(100, Math.round((prob || 0) * 100)));
  document.getElementById("meterBar").style.width = `${pct}%`;
  document.getElementById("probText").textContent = `${fmt(prob)} (${pct}%)`;

  const badge = document.getElementById("riskBadge");
  const label = document.getElementById("riskLabel");

  let mode = pred || "—";
  if (mode === "legit") mode = "Likely Legit";
  if (mode === "fraud") mode = "Likely Fraud";
  label.textContent = mode;

  badge.className = "badge";
  if (pred === "legit") { badge.classList.add("green"); badge.textContent = "Legit"; }
  else if (pred === "fraud") { badge.classList.add("red"); badge.textContent = "Fraud"; }
  else { badge.classList.add("amber"); badge.textContent = "Suspicious"; }
}

function addHistory(entry){
  const cur = JSON.parse(localStorage.getItem(KEY) || "[]");
  cur.unshift({ ts: new Date().toISOString(), ...entry });
  localStorage.setItem(KEY, JSON.stringify(cur.slice(0, 80)));
  renderHistory();
  renderStats();
}

function renderStats(){
  const cur = JSON.parse(localStorage.getItem(KEY) || "[]");
  const scans = cur.length;
  const fraud = cur.filter(x => x.prediction === "fraud").length;
  const legit = cur.filter(x => x.prediction === "legit").length;

  document.getElementById("statScans").textContent = scans;
  document.getElementById("statFraud").textContent = fraud;
  document.getElementById("statLegit").textContent = legit;
}

function renderHistory(){
  const cur = JSON.parse(localStorage.getItem(KEY) || "[]");
  const root = document.getElementById("history");
  root.innerHTML = "";

  if (!cur.length){
    root.innerHTML = `<div class="muted">No history yet.</div>`;
    return;
  }

  cur.forEach(it => {
    const div = document.createElement("div");
    div.className = "histItem";
    div.innerHTML = `
      <div class="histTop">
        <div>
          <div class="histKind">${it.kind}</div>
          <div class="muted">${new Date(it.ts).toLocaleString()}</div>
        </div>
        <div class="mono">${(it.prediction||"").toUpperCase()} • ${fmt(it.probability)}</div>
      </div>
      <div style="margin-top:10px;"><b>${(it.subject||"").slice(0,140)}</b></div>
      <div class="muted" style="margin-top:6px;">${(it.from||"").slice(0,160)}</div>
    `;
    root.appendChild(div);
  });
}

function chipsFromFeatures(engineered){
  const box = document.getElementById("signalsBox");
  if (!engineered){
    box.innerHTML = `<div class="muted">Run a scan to view signals.</div>`;
    return;
  }

  const items = Object.entries(engineered).map(([k,v]) => {
    let cls = "warn";
    if (k.includes("requests_sensitive") && v) cls = "bad";
    if (k.includes("has_urgency") && v) cls = "warn";
    if (k.includes("has_ip_url") && v) cls = "bad";
    if (k.includes("has_url_shortener") && v) cls = "warn";
    if (k.includes("has_unsubscribe") && v) cls = "good";
    if ((k.includes("digit_count") || k.includes("hyphen_count")) && v > 0) cls = "warn";
    if (typeof v === "number" && v === 0) cls = "good";

    return `<span class="chip ${cls}"><b>${k}</b>: ${typeof v==="number"?fmt(v):v}</span>`;
  }).join("");

  box.innerHTML = `<div class="chips">${items}</div>`;
}

function renderReport(report, targetId="reportBox"){
  const box = document.getElementById(targetId);
  if (!report){
    box.innerHTML = `<div class="muted">Run a scan to view report.</div>`;
    return;
  }

  const s = report.summary || {};
  const risks = report.risk_indicators || [];
  const goods = report.legit_indicators || [];
  const headers = report.header_notes || [];

  box.innerHTML = `
    <div class="report">
      <h3>Decision</h3>
      <ul>
        <li><b>Prediction:</b> ${s.prediction}</li>
        <li><b>Probability:</b> ${fmt(s.probability)}</li>
        <li><b>Threshold:</b> ${fmt(s.threshold)}</li>
        <li><b>Override:</b> ${s.override_reason}</li>
      </ul>

      <h3>Risk Indicators</h3>
      <ul>${risks.map(x=>`<li>${x}</li>`).join("")}</ul>

      ${goods.length ? `
        <h3>Legit Indicators</h3>
        <ul>${goods.map(x=>`<li>${x}</li>`).join("")}</ul>
      ` : ""}

      ${headers.length ? `
        <h3>Header Notes</h3>
        <ul>${headers.map(x=>`<li>${x}</li>`).join("")}</ul>
      ` : ""}
    </div>
  `;
}

async function postJSON(url, payload){
  const res = await fetch(url, {
    method: "POST",
    headers: {"Content-Type":"application/json"},
    body: JSON.stringify(payload)
  });
  const data = await res.json();
  if (!res.ok) throw new Error(data.error || "Request failed");
  return data;
}

// Tabs
document.querySelectorAll(".tab").forEach(btn => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab").forEach(x => x.classList.remove("active"));
    document.querySelectorAll(".tabpane").forEach(x => x.classList.remove("active"));
    btn.classList.add("active");
    const pane = document.getElementById(`tab-${btn.dataset.tab}`);
    if (pane) pane.classList.add("active");
  });
});

// Manual analyze
document.getElementById("analyzeBtn").addEventListener("click", async () => {
  const subject = document.getElementById("subject").value;
  const sender_email = document.getElementById("sender_email").value;
  const body = document.getElementById("body").value;

  const out = document.getElementById("manualOut");
  out.textContent = "Analyzing...";

  try{
    const r = await postJSON("/predict", {subject, sender_email, body});
    LAST_JSON = r;

    out.textContent = JSON.stringify(r, null, 2);
    document.getElementById("thresholdPill").textContent = `Threshold: ${r.report?.summary?.threshold ?? "—"}`;

    setRisk(r.probability, r.prediction);
    chipsFromFeatures(r.engineered_features);
    renderReport(r.report, "reportBox");

    addHistory({ kind:"Manual", subject, from: sender_email, prediction:r.prediction, probability:r.probability });
  }catch(e){
    out.textContent = "Error: " + e.message;
  }
});

// Demo
document.getElementById("fillDemoBtn").addEventListener("click", () => {
  document.getElementById("subject").value = "Action required: Verify your account";
  document.getElementById("sender_email").value = "security@paypaI-support.com";
  document.getElementById("body").value =
`Hi,

Your account has been suspended due to unusual activity.
Please verify your password and OTP to restore access.

Click here: http://example-login-security.com/verify

Regards`;
});

// Export JSON
document.getElementById("exportJsonBtn").addEventListener("click", () => {
  if (!LAST_JSON) return alert("Analyze an email first.");
  const blob = new Blob([JSON.stringify(LAST_JSON, null, 2)], {type:"application/json"});
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "hamisecure_analysis.json";
  a.click();
});

// IMAP scan
document.getElementById("imapScanBtn").addEventListener("click", async () => {
  const out = document.getElementById("imapOut");
  out.textContent = "Scanning...";

  try{
    const r = await postJSON("/imap/scan_ui", {
      imap_host: document.getElementById("imap_host").value.trim(),
      imap_port: parseInt(document.getElementById("imap_port").value.trim() || "993", 10),
      imap_ssl: document.getElementById("imap_ssl").checked,
      imap_user: document.getElementById("imap_user").value.trim(),
      imap_password: document.getElementById("imap_password").value,
      imap_folder: document.getElementById("imap_folder").value.trim() || "INBOX",
      limit: parseInt(document.getElementById("imap_limit").value.trim() || "10", 10)
    });

    out.textContent = JSON.stringify(r, null, 2);

    const tbody = document.querySelector("#imapTable tbody");
    tbody.innerHTML = "";

    if (!r.results || !r.results.length){
      tbody.innerHTML = `<tr><td colspan="4" class="muted">No emails fetched.</td></tr>`;
      return;
    }

    r.results.forEach((it, idx) => {
      const tr = document.createElement("tr");
      tr.innerHTML = `
        <td><b>${it.prediction}</b></td>
        <td class="mono">${fmt(it.probability)}</td>
        <td>${(it.from||"").slice(0,40)}</td>
        <td>${(it.subject||"").slice(0,60)}</td>
      `;
      tr.addEventListener("click", () => {
        setRisk(it.probability, it.prediction);
        renderReport(it.report, "imapDetail");
        addHistory({ kind:"IMAP", subject: it.subject, from: it.from, prediction: it.prediction, probability: it.probability });
      });
      tbody.appendChild(tr);
      if (idx === 0) tr.click();
    });

  }catch(e){
    out.textContent = "Error: " + e.message;
  }
});

// File upload analyze
document.getElementById("uploadAnalyzeBtn").addEventListener("click", async () => {
  const fileInput = document.getElementById("uploadFile");
  const out = document.getElementById("fileOut");
  const rep = document.getElementById("fileReport");

  if (!fileInput.files || !fileInput.files[0]) {
    alert("Choose a file first.");
    return;
  }

  out.textContent = "Uploading + analyzing...";
  rep.textContent = "Analyzing...";

  try{
    const fd = new FormData();
    fd.append("file", fileInput.files[0]);

    const res = await fetch("/upload/analyze", { method:"POST", body: fd });
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Upload failed");

    out.textContent = JSON.stringify(data, null, 2);
    setRisk(data.probability, data.prediction);
    renderReport(data.report, "fileReport");

    addHistory({
      kind:"File",
      subject: data.parsed?.subject || "(file)",
      from: data.parsed?.sender_email || "",
      prediction: data.prediction,
      probability: data.probability
    });
  }catch(e){
    out.textContent = "Error: " + e.message;
    rep.textContent = "Error: " + e.message;
  }
});

document.getElementById("clearFileBtn").addEventListener("click", () => {
  document.getElementById("uploadFile").value = "";
  document.getElementById("fileOut").textContent = "—";
  document.getElementById("fileReport").textContent = "Upload a file to view report.";
});

// Clear history
document.getElementById("clearHistoryBtn").addEventListener("click", () => {
  localStorage.removeItem(KEY);
  renderHistory();
  renderStats();
});

// init
renderHistory();
renderStats();

