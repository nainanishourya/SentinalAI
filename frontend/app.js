// ============ Config ============
const PIPELINE_ORDER = [
  { key: "orchestrator", label: "Orchestrator", mono: "OR" },
  { key: "log_ingestion", label: "Log Ingestion", mono: "LI" },
  { key: "detection_engine", label: "Detection Engine", mono: "DE" },
  { key: "incident_creation", label: "Incident Creation", mono: "IC" },
  { key: "detection_analyst", label: "Detection Analyst", mono: "DA" },
  { key: "threat_intel", label: "Threat Intel", mono: "TI" },
  { key: "attack_reconstruction", label: "Attack Reconstruction", mono: "AR" },
  { key: "root_cause", label: "Root Cause", mono: "RC" },
  { key: "mitre_mapper", label: "MITRE Mapper", mono: "MM" },
  { key: "incident_response", label: "Response Plan", mono: "IR" },
];

const CATEGORY_ORDER = [
  "Credential Access", "Initial Access", "Impact", "Reconnaissance",
  "Privilege Escalation", "Exfiltration", "Lateral Movement",
  "Command and Control", "Defense Evasion",
];

const SEVERITY_STATUS = { critical: "critical", high: "serious", medium: "warning", low: "good" };

function cssVar(name) {
  return getComputedStyle(document.documentElement).getPropertyValue(name).trim();
}

function seriesColor(index) {
  const slots = ["--series-1", "--series-2", "--series-3", "--series-4", "--series-5", "--series-6", "--series-7", "--series-8"];
  if (index < slots.length) return cssVar(slots[index]);
  return cssVar("--series-other");
}

function categoryColor(category) {
  const idx = CATEGORY_ORDER.indexOf(category);
  return seriesColor(idx === -1 ? 8 : idx);
}

const _dynamicColorMap = {};
function dynamicColor(key) {
  if (!(key in _dynamicColorMap)) {
    _dynamicColorMap[key] = seriesColor(Object.keys(_dynamicColorMap).length);
  }
  return _dynamicColorMap[key];
}

function statusColor(status) {
  return cssVar(`--status-${status}`);
}

function fmtTime(iso) {
  try { return new Date(iso).toLocaleTimeString(); } catch { return iso; }
}
function fmtDateTime(iso) {
  try { return new Date(iso).toLocaleString(); } catch { return iso; }
}
function esc(str) {
  const d = document.createElement("div");
  d.textContent = str == null ? "" : String(str);
  return d.innerHTML;
}

// ============ Clock ============
setInterval(() => {
  document.getElementById("clock").textContent = new Date().toLocaleTimeString();
}, 1000);

// ============ WebSocket ============
let ws;
function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => setWsStatus(true);
  ws.onclose = () => { setWsStatus(false); setTimeout(connectWs, 2000); };
  ws.onerror = () => ws.close();
  ws.onmessage = (evt) => handleWsMessage(JSON.parse(evt.data));
}
function setWsStatus(online) {
  const dot = document.getElementById("ws-dot");
  const label = document.getElementById("ws-label");
  dot.className = "dot " + (online ? "online" : "offline");
  label.textContent = online ? "Live" : "Reconnecting…";
}

function handleWsMessage(msg) {
  switch (msg.type) {
    case "ambient_log":
      consoleLine("ambient", `<span class="tag">[traffic]</span> ${esc(msg.line)}`);
      break;
    case "pipeline_start":
      resetPipelineViz();
      setPipelineStatus(`Running: ${msg.scenario} (source: ${msg.source})`);
      consoleLine("trace", `<span class="tag">[pipeline]</span> Started analysis of <strong>${esc(msg.scenario)}</strong>`);
      setSimulateBusy(true);
      break;
    case "agent_step":
      markNode(msg.node);
      if (msg.trace) {
        const llmTag = msg.trace.llm_backed === true ? " <span class=\"tag\">(LLM)</span>" : "";
        consoleLine("trace", `<span class="agent">${esc(msg.trace.agent)}</span>${llmTag}: ${esc(msg.trace.message)}`);
      }
      break;
    case "incident_complete":
      finishPipelineViz(true);
      setPipelineStatus(`Incident ${msg.incident.id} created — ${msg.incident.category} (${msg.incident.severity})`);
      consoleLine("incident", `[INCIDENT] ${msg.incident.id} — ${msg.incident.attack_type} — accuracy ${msg.incident.accuracy_score}%`);
      setSimulateBusy(false);
      refreshAll();
      break;
    case "pipeline_benign":
      finishPipelineViz(false);
      setPipelineStatus(`No incident: '${msg.scenario}' classified as benign.`);
      consoleLine("ambient", `<span class="tag">[pipeline]</span> Traffic classified as benign — no incident created.`);
      setSimulateBusy(false);
      break;
    case "pipeline_error":
      setPipelineStatus("Pipeline error — see server logs.");
      setSimulateBusy(false);
      break;
    case "upload_event":
      renderUploadHistoryItem(msg.event);
      if (msg.event.verdict === "rejected") {
        consoleLine("upload-block", `[UPLOAD BLOCKED] ${esc(msg.event.filename)} — ${esc(msg.event.reason)}`);
      }
      if (msg.event.incident_id && msg.event.id === lastUploadEventId) {
        showIncidentLinkInVerdict(msg.event.incident_id);
      }
      refreshStats();
      if (msg.event.incident_id) refreshIncidents();
      break;
  }
}

function consoleLine(cls, html) {
  const el = document.getElementById("live-console");
  const line = document.createElement("div");
  line.className = "console-line " + cls;
  line.innerHTML = `<span class="tag">${new Date().toLocaleTimeString()}</span> ${html}`;
  el.appendChild(line);
  el.scrollTop = el.scrollHeight;
  while (el.children.length > 300) el.removeChild(el.firstChild);
}

// ============ Pipeline viz ============
function buildPipelineViz() {
  const container = document.getElementById("pipeline-viz");
  container.innerHTML = "";
  PIPELINE_ORDER.forEach((node, i) => {
    const wrap = document.createElement("div");
    wrap.className = "pipe-node";
    wrap.id = `pipe-node-${node.key}`;
    wrap.innerHTML = `<div class="pipe-node-circle">${node.mono}</div><div class="pipe-node-label">${node.label}</div>`;
    container.appendChild(wrap);
    if (i < PIPELINE_ORDER.length - 1) {
      const edge = document.createElement("div");
      edge.className = "pipe-edge";
      container.appendChild(edge);
    }
  });
}
function resetPipelineViz() {
  PIPELINE_ORDER.forEach((n) => {
    const el = document.getElementById(`pipe-node-${n.key}`);
    if (el) el.className = "pipe-node";
  });
}
function markNode(key) {
  PIPELINE_ORDER.forEach((n) => {
    const el = document.getElementById(`pipe-node-${n.key}`);
    if (!el) return;
    if (n.key === key) el.className = "pipe-node active";
    else if (el.className === "pipe-node active") el.className = "pipe-node done";
  });
}
function finishPipelineViz(malicious) {
  PIPELINE_ORDER.forEach((n) => {
    const el = document.getElementById(`pipe-node-${n.key}`);
    if (!el) return;
    if (el.className.includes("active") || el.className.includes("done")) el.className = "pipe-node done";
    else if (!malicious) el.className = "pipe-node skipped";
  });
}
function setPipelineStatus(text) {
  document.getElementById("pipeline-status").textContent = text;
}
function setSimulateBusy(busy) {
  const btn = document.getElementById("simulate-btn");
  btn.disabled = busy;
  btn.querySelector(".btn-icon").textContent = busy ? "…" : "▶";
}

// ============ Charts ============
let chartCategory, chartSeverity, chartAccuracy, chartMitre;

function baseChartOptions(extra = {}) {
  return Object.assign({
    responsive: true,
    maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: {
        backgroundColor: cssVar("--surface-2"),
        titleColor: cssVar("--text-primary"),
        bodyColor: cssVar("--text-secondary"),
        borderColor: cssVar("--border"),
        borderWidth: 1,
        padding: 10,
      },
    },
  }, extra);
}

function initCharts() {
  const gridColor = cssVar("--gridline");
  const tickColor = cssVar("--text-muted");

  chartCategory = new Chart(document.getElementById("chart-category"), {
    type: "bar",
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderRadius: 4, barThickness: 18 }] },
    options: baseChartOptions({
      indexAxis: "y",
      scales: {
        x: { beginAtZero: true, ticks: { color: tickColor, precision: 0 }, grid: { color: gridColor } },
        y: { ticks: { color: tickColor }, grid: { display: false } },
      },
    }),
  });

  chartSeverity = new Chart(document.getElementById("chart-severity"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor: cssVar("--surface-1"), borderWidth: 2 }] },
    options: baseChartOptions({ cutout: "62%" }),
  });

  chartAccuracy = new Chart(document.getElementById("chart-accuracy"), {
    type: "line",
    data: { labels: [], datasets: [{ data: [], borderColor: cssVar("--series-1"), backgroundColor: "transparent", borderWidth: 2, pointRadius: 3, pointBackgroundColor: cssVar("--series-1"), tension: 0.25 }] },
    options: baseChartOptions({
      scales: {
        x: { ticks: { color: tickColor, maxRotation: 0 }, grid: { display: false } },
        y: { min: 0, max: 100, ticks: { color: tickColor }, grid: { color: gridColor } },
      },
    }),
  });

  chartMitre = new Chart(document.getElementById("chart-mitre"), {
    type: "bar",
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderRadius: 4, barThickness: 18 }] },
    options: baseChartOptions({
      indexAxis: "y",
      scales: {
        x: { beginAtZero: true, ticks: { color: tickColor, precision: 0 }, grid: { color: gridColor } },
        y: { ticks: { color: tickColor }, grid: { display: false } },
      },
    }),
  });
}

function renderLegend(elId, entries) {
  const el = document.getElementById(elId);
  el.innerHTML = entries.map(e => `<span class="legend-item"><span class="legend-swatch" style="background:${e.color}"></span>${esc(e.label)} (${e.value})</span>`).join("");
}

function updateChartsFromIncidents(incidents) {
  // Category distribution
  const catCounts = {};
  incidents.forEach(i => { const c = i.category || "Unknown"; catCounts[c] = (catCounts[c] || 0) + 1; });
  const catEntries = Object.entries(catCounts).sort((a, b) => b[1] - a[1]);
  chartCategory.data.labels = catEntries.map(e => e[0]);
  chartCategory.data.datasets[0].data = catEntries.map(e => e[1]);
  chartCategory.data.datasets[0].backgroundColor = catEntries.map(e => categoryColor(e[0]));
  chartCategory.update();
  renderLegend("legend-category", catEntries.map(([label, value]) => ({ label, value, color: categoryColor(label) })));

  // Severity breakdown
  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  incidents.forEach(i => { if (i.severity in sevCounts) sevCounts[i.severity]++; });
  const sevEntries = Object.entries(sevCounts).filter(([, v]) => v > 0);
  chartSeverity.data.labels = sevEntries.map(e => e[0]);
  chartSeverity.data.datasets[0].data = sevEntries.map(e => e[1]);
  chartSeverity.data.datasets[0].backgroundColor = sevEntries.map(([sev]) => statusColor(SEVERITY_STATUS[sev]));
  chartSeverity.update();
  renderLegend("legend-severity", sevEntries.map(([label, value]) => ({ label, value, color: statusColor(SEVERITY_STATUS[label]) })));

  // Accuracy trend (chronological, oldest to newest, last 20)
  const withScores = incidents.filter(i => typeof i.accuracy_score === "number").slice().reverse().slice(-20);
  chartAccuracy.data.labels = withScores.map(i => fmtTime(i.created_at));
  chartAccuracy.data.datasets[0].data = withScores.map(i => i.accuracy_score);
  chartAccuracy.update();

  // MITRE tactic frequency
  const tacticCounts = {};
  incidents.forEach(i => {
    const techniques = (i.mitre_mapping && i.mitre_mapping.techniques) || [];
    techniques.forEach(t => { if (t.tactic) tacticCounts[t.tactic] = (tacticCounts[t.tactic] || 0) + 1; });
  });
  const tacticEntries = Object.entries(tacticCounts).sort((a, b) => b[1] - a[1]).slice(0, 10);
  chartMitre.data.labels = tacticEntries.map(e => e[0]);
  chartMitre.data.datasets[0].data = tacticEntries.map(e => e[1]);
  chartMitre.data.datasets[0].backgroundColor = tacticEntries.map(([t]) => dynamicColor(t));
  chartMitre.update();
}

// ============ KPIs ============
async function refreshStats() {
  const stats = await fetch("/api/stats").then(r => r.json());
  document.getElementById("kpi-total").textContent = stats.total_incidents;
  const critical = (stats.by_severity.find(s => s.severity === "critical") || {}).c || 0;
  document.getElementById("kpi-critical").textContent = critical;
  document.getElementById("kpi-accuracy").textContent = stats.avg_accuracy != null ? `${stats.avg_accuracy}%` : "—";
  document.getElementById("kpi-confidence").textContent = stats.avg_confidence != null ? `${stats.avg_confidence}%` : "—";
  document.getElementById("kpi-uploads").textContent = stats.uploads_blocked;
}

// ============ Incidents table ============
let incidentsCache = [];

function severityBadge(sev) {
  return `<span class="badge badge-${sev}">${esc(sev)}</span>`;
}

async function refreshIncidents() {
  incidentsCache = await fetch("/api/incidents").then(r => r.json());
  const tbody = document.getElementById("incidents-tbody");
  if (!incidentsCache.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="muted empty-row">No incidents yet — run a simulation to begin.</td></tr>`;
  } else {
    tbody.innerHTML = incidentsCache.map(inc => `
      <tr data-id="${esc(inc.id)}">
        <td class="mono">${esc(inc.id)}</td>
        <td>${esc(inc.attack_type)}</td>
        <td>${esc(inc.category)}</td>
        <td>${severityBadge(inc.severity)}</td>
        <td class="mono">${inc.accuracy_score != null ? inc.accuracy_score + "%" : "—"}</td>
        <td class="mono">${inc.confidence_score != null ? inc.confidence_score + "%" : "—"}</td>
        <td>${esc(inc.source)}</td>
        <td class="mono">${fmtTime(inc.created_at)}</td>
      </tr>`).join("");
    tbody.querySelectorAll("tr").forEach(tr => {
      tr.addEventListener("click", () => openIncidentModal(tr.dataset.id));
    });
  }
  updateChartsFromIncidents(incidentsCache);
}

// ============ Modal ============
function llmTag(backed) {
  return backed ? '<span class="llm-tag">LLM-generated</span>' : '<span class="llm-tag">fallback logic</span>';
}

function openIncidentModal(id) {
  const inc = incidentsCache.find(i => i.id === id);
  if (!inc) return;
  document.getElementById("modal-title").textContent = `${inc.id} — ${inc.attack_type}`;

  const mitre = (inc.mitre_mapping && inc.mitre_mapping.techniques) || [];
  const analyst = inc.analyst_findings || {};
  const intel = inc.threat_intel || {};
  const recon = inc.reconstruction || {};
  const rootCause = inc.root_cause || {};
  const plan = inc.response_plan || {};
  const acc = inc.accuracy || {};

  const respSection = (title, arr) => (arr && arr.length) ? `<h3>${title}</h3><ul>${arr.map(a => `<li>${esc(a)}</li>`).join("")}</ul>` : "";

  document.getElementById("modal-body").innerHTML = `
    <div class="report-section">
      <div class="score-row">
        <div class="score-tile"><div class="v">${inc.accuracy_score ?? "—"}%</div><div class="l">Prediction Accuracy</div></div>
        <div class="score-tile"><div class="v">${inc.confidence_score ?? "—"}%</div><div class="l">Analyst Confidence</div></div>
        <div class="score-tile"><div class="v">${severityBadge(inc.severity)}</div><div class="l">Severity</div></div>
        <div class="score-tile"><div class="v">${esc(inc.source)}</div><div class="l">Source</div></div>
      </div>
      <p class="muted small">Accuracy = 65% MITRE technique overlap (${acc.mitre_overlap_score ?? "—"}%) + 35% category match (${acc.category_match_score ?? "—"}%) vs. ground truth.</p>
    </div>

    <div class="report-section">
      <h3>Detection Analyst ${llmTag(analyst.llm_backed)}</h3>
      <p>${esc(analyst.summary || "—")}</p>
      ${analyst.suspicious_patterns ? `<ul>${analyst.suspicious_patterns.map(p => `<li>${esc(p)}</li>`).join("")}</ul>` : ""}
    </div>

    <div class="report-section">
      <h3>Threat Intelligence ${llmTag(intel.llm_backed)}</h3>
      <p>${esc(intel.likely_campaign_or_actor_profile || intel.summary || "—")}</p>
      ${intel.ioc_context ? `<ul>${intel.ioc_context.map(p => `<li>${esc(p)}</li>`).join("")}</ul>` : ""}
      ${intel.intel_note ? `<p class="muted small">${esc(intel.intel_note)}</p>` : ""}
    </div>

    <div class="report-section">
      <h3>Attack Reconstruction ${llmTag(recon.llm_backed)}</h3>
      <p>${esc(recon.narrative || recon.summary || "—")}</p>
      ${recon.timeline ? `<ul class="timeline">${recon.timeline.map(t => `<li><span class="step-num">${t.step ?? ""}</span>${esc(t.description)}</li>`).join("")}</ul>` : ""}
    </div>

    <div class="report-section">
      <h3>Root Cause ${llmTag(rootCause.llm_backed)}</h3>
      <p>${esc(rootCause.root_cause || rootCause.summary || "—")}</p>
      ${rootCause.contributing_factors ? `<ul>${rootCause.contributing_factors.map(p => `<li>${esc(p)}</li>`).join("")}</ul>` : ""}
    </div>

    <div class="report-section">
      <h3>MITRE ATT&amp;CK Mapping</h3>
      <div class="chip-row">
        ${mitre.map(t => `<span class="chip"><strong>${esc(t.technique_id)}</strong> ${esc(t.technique_name)} <span class="muted">(${esc(t.tactic)})</span></span>`).join("") || '<span class="muted">No techniques mapped.</span>'}
      </div>
    </div>

    <div class="report-section">
      <h3>Incident Response Plan ${llmTag(plan.llm_backed)}</h3>
      ${respSection("Immediate Actions", plan.immediate_actions)}
      ${respSection("Containment", plan.containment)}
      ${respSection("Eradication", plan.eradication)}
      ${respSection("Recovery", plan.recovery)}
      ${respSection("Preventive", plan.preventive)}
    </div>

    <div class="report-section">
      <h3>Raw Correlated Logs</h3>
      <div class="raw-logs">${(inc.raw_logs || []).map(esc).join("\n")}</div>
    </div>

    <div class="report-section">
      <h3>Full Agent Trace</h3>
      <ul class="timeline">${(inc.trace || []).map(t => `<li><span class="step-num">${fmtTime(t.timestamp)}</span><strong>${esc(t.agent)}:</strong>&nbsp;${esc(t.message)}</li>`).join("")}</ul>
    </div>
  `;
  document.getElementById("modal-backdrop").classList.add("open");
}

document.getElementById("modal-close").addEventListener("click", closeModal);
document.getElementById("modal-backdrop").addEventListener("click", (e) => { if (e.target.id === "modal-backdrop") closeModal(); });
function closeModal() { document.getElementById("modal-backdrop").classList.remove("open"); }

// ============ Simulate control ============
async function loadScenarios() {
  const scenarios = await fetch("/api/scenarios").then(r => r.json());
  const select = document.getElementById("scenario-select");
  scenarios.forEach(s => {
    const opt = document.createElement("option");
    opt.value = s.id;
    opt.textContent = `${s.name} (${s.severity})`;
    select.appendChild(opt);
  });
}

document.getElementById("simulate-btn").addEventListener("click", async () => {
  const scenarioId = document.getElementById("scenario-select").value || null;
  setSimulateBusy(true);
  await fetch("/api/simulate", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scenario_id: scenarioId }),
  });
});

// ============ Upload scanner ============
const dropzone = document.getElementById("dropzone");
const uploadInput = document.getElementById("upload-input");
dropzone.addEventListener("click", () => uploadInput.click());
dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("drag"); });
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag"));
dropzone.addEventListener("drop", (e) => {
  e.preventDefault();
  dropzone.classList.remove("drag");
  if (e.dataTransfer.files.length) submitUpload(e.dataTransfer.files[0]);
});
uploadInput.addEventListener("change", () => {
  if (uploadInput.files.length) submitUpload(uploadInput.files[0]);
});

let lastUploadEventId = null;

async function submitUpload(file) {
  const resultEl = document.getElementById("upload-result");
  resultEl.innerHTML = `<div class="upload-verdict">Scanning "${esc(file.name)}"…</div>`;
  const form = new FormData();
  form.append("file", file);
  const resp = await fetch("/api/upload", { method: "POST", body: form });
  const data = await resp.json();
  const ok = data.verdict === "accepted";
  lastUploadEventId = data.event_id;
  resultEl.innerHTML = `
    <div class="upload-verdict ${data.verdict}">
      <div class="upload-verdict-title">${ok ? "✔ Accepted" : "✕ Invalid File Type"}</div>
      <div>Declared: <strong>.${esc(data.declared_ext || "?")}</strong> &middot; Detected: <strong>${esc(data.detected_type || "?")}</strong></div>
      <div class="muted small">${esc(data.reason)}</div>
      ${!ok ? `<div class="small" id="upload-incident-status">Investigating via 9-agent SOC pipeline…</div>` : ""}
    </div>`;
  uploadInput.value = "";
}

function showIncidentLinkInVerdict(incidentId) {
  const statusEl = document.getElementById("upload-incident-status");
  if (!statusEl) return;
  statusEl.innerHTML = `Triggered incident <a href="#" id="jump-incident">${esc(incidentId)}</a> — analyzed by all 9 SOC agents.`;
  document.getElementById("jump-incident").addEventListener("click", async (e) => {
    e.preventDefault();
    await refreshIncidents();
    openIncidentModal(incidentId);
  });
}

function renderUploadHistoryItem(event) {
  const el = document.getElementById("upload-history");
  const item = document.createElement("div");
  item.className = "upload-history-item";
  item.innerHTML = `<span>${esc(event.filename)}</span><span style="color:${event.verdict === "rejected" ? "var(--status-critical)" : "var(--status-good)"}">${esc(event.verdict)}</span>`;
  el.prepend(item);
  while (el.children.length > 20) el.removeChild(el.lastChild);
}

async function loadUploadHistory() {
  const events = await fetch("/api/uploads").then(r => r.json());
  const el = document.getElementById("upload-history");
  el.innerHTML = "";
  events.forEach(renderUploadHistoryItem);
}

// ============ Init ============
async function refreshAll() {
  await Promise.all([refreshStats(), refreshIncidents()]);
}

(async function init() {
  buildPipelineViz();
  initCharts();
  connectWs();
  await loadScenarios();
  await loadUploadHistory();
  await refreshAll();
})();
