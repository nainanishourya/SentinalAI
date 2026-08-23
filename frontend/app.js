// ============ Config ============
const PIPELINE = [
  { key: "orchestrator", label: "Orchestrator", tone: "iris" },
  { key: "log_ingestion", label: "Log Ingestion", tone: "bone" },
  { key: "detection_engine", label: "Detection Engine", tone: "teal" },
  { key: "incident_creation", label: "Incident Creation", tone: "amber" },
  { key: "detection_analyst", label: "Detection Analyst", tone: "sage" },
  { key: "threat_intel", label: "Threat Intel", tone: "iris" },
  { key: "attack_reconstruction", label: "Attack Reconstruction", tone: "teal" },
  { key: "root_cause", label: "Root Cause", tone: "amber" },
  { key: "mitre_mapper", label: "MITRE Mapper", tone: "sage" },
  { key: "incident_response", label: "Response Plan", tone: "teal" },
];

const TONE_VAR = { teal: "--teal", sage: "--sage", amber: "--amber", terracotta: "--terracotta", iris: "--iris", bone: "--bone-dim" };
function toneColor(tone) { return cssVar(TONE_VAR[tone] || "--bone-dim"); }

const CATEGORY_ORDER = [
  "Credential Access", "Initial Access", "Impact", "Reconnaissance",
  "Privilege Escalation", "Exfiltration", "Lateral Movement",
  "Command and Control", "Defense Evasion",
];
const CATEGORY_SLOTS = ["--cat-1", "--cat-2", "--cat-3", "--cat-4", "--cat-5", "--cat-6", "--cat-7", "--cat-8"];
const SEVERITY_VAR = { critical: "--sev-critical", high: "--sev-high", medium: "--sev-medium", low: "--sev-low" };

function cssVar(name) { return getComputedStyle(document.documentElement).getPropertyValue(name).trim(); }
function categoryColor(cat) {
  const idx = CATEGORY_ORDER.indexOf(cat);
  return idx === -1 || idx >= CATEGORY_SLOTS.length ? cssVar("--cat-other") : cssVar(CATEGORY_SLOTS[idx]);
}
const _dynColor = {};
function dynamicColor(key) {
  if (!(key in _dynColor)) _dynColor[key] = CATEGORY_SLOTS[Object.keys(_dynColor).length % CATEGORY_SLOTS.length];
  return cssVar(_dynColor[key]);
}
function severityColor(sev) { return cssVar(SEVERITY_VAR[sev] || "--bone-dim"); }

function fmtTime(iso) { try { return new Date(iso).toLocaleTimeString("en-GB", { hour12: false }); } catch { return "--:--:--"; } }
function esc(str) { const d = document.createElement("div"); d.textContent = str == null ? "" : String(str); return d.innerHTML; }

// ============ Clock ============
setInterval(() => { document.getElementById("clock").textContent = new Date().toLocaleTimeString("en-GB", { hour12: false }); }, 1000);

// ============ Health ============
fetch("/api/health").then(r => r.json()).then(h => {
  document.getElementById("chip-model").textContent = h.model || (h.llm_configured ? "configured" : "not configured");
}).catch(() => {});

// ============ WebSocket ============
let ws;
let sessionRuns = 0;
function connectWs() {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => setWsStatus(true);
  ws.onclose = () => { setWsStatus(false); setTimeout(connectWs, 2000); };
  ws.onerror = () => ws.close();
  ws.onmessage = (evt) => handleWsMessage(JSON.parse(evt.data));
}
function setWsStatus(online) {
  const led = document.getElementById("ws-led");
  led.dataset.on = online ? "true" : "false";
  led.dataset.pulse = online ? "false" : "true";
  led.style.setProperty("--led-color", online ? cssVar("--sage") : cssVar("--terracotta"));
  document.getElementById("ws-label").textContent = online ? "live" : "reconnecting";
}
function setAnalyzing(on) {
  document.getElementById("pipeline-analyzing-chip").style.display = on ? "" : "none";
}

let livePinned = false; // true once user pins an incident from the table

function handleWsMessage(msg) {
  switch (msg.type) {
    case "ambient_log":
      consoleLine("var(--bone-faint)", "·", "system", esc(msg.line));
      break;
    case "pipeline_start":
      sessionRuns += 1;
      document.getElementById("kpi-runs").textContent = sessionRuns;
      resetPipeline();
      setAnalyzing(true);
      consoleLine("var(--teal)", "·", "pipeline", `Started analysis of <strong>${esc(msg.scenario)}</strong> (source: ${esc(msg.source)})`);
      if (!livePinned) renderRightPanelLive({ name: msg.scenario, source: msg.source });
      break;
    case "agent_step":
      markNode(msg.node);
      if (msg.trace) {
        const pipelineNode = PIPELINE.find(p => p.key === msg.node);
        const tone = pipelineNode?.tone || "bone";
        const shortLabel = pipelineNode?.label || msg.trace.agent;
        consoleLine(toneColor(tone), "→", shortLabel, esc(msg.trace.message) + (msg.trace.llm_backed ? ' <span class="mono muted">(LLM)</span>' : ""));
        updateNodeMessage(msg.node, msg.trace.message, msg.trace.llm_backed);
      }
      if (!livePinned) renderRightPanelLive(msg.state);
      break;
    case "incident_complete":
      finishPipeline(true);
      setAnalyzing(false);
      consoleLine("var(--terracotta)", "✓", "incident", `${msg.incident.id} — ${esc(msg.incident.attack_type)} — accuracy ${msg.incident.accuracy_score}%`);
      document.getElementById("latest-report-btn").disabled = false;
      document.getElementById("latest-report-btn").onclick = () => { refreshIncidents().then(() => openIncidentModal(msg.incident.id)); };
      if (!livePinned) renderRightPanelIncident(msg.incident);
      refreshAll();
      break;
    case "pipeline_benign":
      finishPipeline(false);
      setAnalyzing(false);
      consoleLine("var(--bone-faint)", "·", "pipeline", `'${esc(msg.scenario)}' classified as benign — no incident created.`);
      if (!livePinned) renderRightPanelEmpty("Last run was classified as benign — no incident opened.");
      break;
    case "pipeline_error":
      setAnalyzing(false);
      consoleLine("var(--terracotta)", "✗", "pipeline", "Pipeline error — see server logs.");
      break;
    case "upload_event":
      renderUploadHistoryItem(msg.event);
      if (msg.event.verdict === "rejected") {
        consoleLine("var(--terracotta)", "✗", "scanner", `Blocked ${esc(msg.event.filename)} — ${esc(msg.event.reason)}`);
      }
      if (msg.event.incident_id && msg.event.id === lastUploadEventId) showIncidentLinkInVerdict(msg.event.incident_id);
      refreshStats();
      if (msg.event.incident_id) refreshIncidents();
      break;
  }
}

function consoleLine(color, mark, agent, html) {
  const el = document.getElementById("live-console");
  const row = document.createElement("div");
  row.className = "event-row fade-rise";
  row.innerHTML = `<time>${new Date().toLocaleTimeString("en-GB", { hour12: false })}</time><span class="agent" style="color:${color}">${esc(agent)}</span><span class="mark" style="color:${color}">${mark}</span><span class="msg">${html}</span>`;
  el.appendChild(row);
  el.scrollTop = el.scrollHeight;
  while (el.children.length > 300) el.removeChild(el.firstChild);
  document.getElementById("event-count").textContent = `${el.children.length} events`;
}

// ============ Pipeline: phase list + agent rail + graph ============
function buildPipeline() {
  const phaseList = document.getElementById("phase-list");
  const track = document.getElementById("graph-track");
  phaseList.innerHTML = ""; track.innerHTML = "";

  PIPELINE.forEach((node, i) => {
    const li = document.createElement("li");
    li.id = `phase-${node.key}`;
    li.innerHTML = `<span class="led" data-on="false"></span><span class="text"><span class="name mono">${node.label}</span><span class="msg">idle</span><span class="bar activity-bar" style="display:none"></span></span>`;
    phaseList.appendChild(li);

    const nodeWrap = document.createElement("div");
    nodeWrap.className = "graph-node-wrap";
    const card = document.createElement("div");
    card.className = "node-card";
    card.id = `node-${node.key}`;
    card.innerHTML = `<div class="head"><span class="led" data-on="false"></span><span class="mono" style="font-size:8.5px;text-transform:uppercase;letter-spacing:0.13em;color:${toneColor(node.tone)}">${String(i + 1).padStart(2, "0")}</span><span class="tag" style="color:var(--bone-faint)"></span></div><div class="title">${node.label}</div><div class="msg" id="node-msg-${node.key}">pending</div>`;
    nodeWrap.appendChild(card);
    track.appendChild(nodeWrap);

    if (i < PIPELINE.length - 1) {
      const edge = document.createElement("div");
      edge.className = "graph-edge";
      edge.id = `edge-${node.key}`;
      track.appendChild(edge);
    }
  });
}

function setNodeState(key, state) {
  const card = document.getElementById(`node-${key}`);
  const phase = document.getElementById(`phase-${key}`);
  if (!card) return;
  const tone = PIPELINE.find(p => p.key === key)?.tone || "bone";

  card.classList.remove("current", "done");
  const led = card.querySelector(".led");
  const tag = card.querySelector(".tag");
  const phaseLed = phase.querySelector(".led");
  const phaseBar = phase.querySelector(".bar");
  const phaseName = phase.querySelector(".name");

  if (state === "current") {
    card.classList.add("current");
    led.dataset.on = "true"; led.dataset.pulse = "true"; led.style.setProperty("--led-color", toneColor(tone));
    tag.textContent = "RUNNING"; tag.style.color = toneColor(tone);
    phaseLed.dataset.on = "true"; phaseLed.dataset.pulse = "true"; phaseLed.style.setProperty("--led-color", toneColor(tone));
    phaseBar.style.display = "";
    phase.classList.add("active-row");
    phaseName.style.color = toneColor(tone);
  } else if (state === "done") {
    card.classList.add("done");
    led.dataset.on = "true"; led.dataset.pulse = "false"; led.style.setProperty("--led-color", toneColor("sage"));
    tag.textContent = "DONE"; tag.style.color = toneColor("sage");
    phaseLed.dataset.on = "true"; phaseLed.dataset.pulse = "false"; phaseLed.style.setProperty("--led-color", toneColor("sage"));
    phaseBar.style.display = "none";
    phase.classList.remove("active-row");
    phaseName.style.color = "var(--bone-dim)";
  } else {
    led.dataset.on = "false"; tag.textContent = "";
    phaseLed.dataset.on = "false";
    phaseBar.style.display = "none";
    phase.classList.remove("active-row");
    phaseName.style.color = "var(--bone-faint)";
  }
}

function resetPipeline() {
  PIPELINE.forEach(n => {
    setNodeState(n.key, "pending");
    document.getElementById(`node-msg-${n.key}`).textContent = "pending";
    document.getElementById(`phase-${n.key}`).querySelector(".msg").textContent = "idle";
    const edge = document.getElementById(`edge-${n.key}`);
    if (edge) edge.classList.remove("animated");
  });
}
function markNode(key) {
  let seenCurrent = false;
  PIPELINE.forEach(n => {
    const el = document.getElementById(`node-${n.key}`);
    if (n.key === key) {
      setNodeState(n.key, "current");
      seenCurrent = true;
      const edge = document.getElementById(`edge-${n.key}`);
      const prevIdx = PIPELINE.findIndex(p => p.key === n.key) - 1;
      if (prevIdx >= 0) { const prevEdge = document.getElementById(`edge-${PIPELINE[prevIdx].key}`); if (prevEdge) prevEdge.classList.add("animated"); }
    } else if (el.classList.contains("current")) {
      setNodeState(n.key, "done");
    }
  });
}
function updateNodeMessage(key, message, llmBacked) {
  const nodeMsg = document.getElementById(`node-msg-${key}`);
  if (nodeMsg) nodeMsg.textContent = message;
  const phaseMsg = document.getElementById(`phase-${key}`)?.querySelector(".msg");
  if (phaseMsg) phaseMsg.textContent = (llmBacked ? "✓ " : "") + message;
}
function finishPipeline(malicious) {
  PIPELINE.forEach(n => {
    const el = document.getElementById(`node-${n.key}`);
    if (el.classList.contains("current")) setNodeState(n.key, "done");
    else if (!malicious && !el.classList.contains("done")) setNodeState(n.key, "pending");
  });
  document.querySelectorAll(".graph-edge").forEach(e => e.classList.remove("animated"));
}

// ============ Tabs ============
document.getElementById("center-tabs").addEventListener("click", (e) => {
  const btn = e.target.closest("button[data-tab]");
  if (!btn) return;
  document.querySelectorAll("#center-tabs button").forEach(b => b.setAttribute("aria-pressed", b === btn));
  document.querySelectorAll(".tab-pane").forEach(p => p.style.display = p.dataset.pane === btn.dataset.tab ? "" : "none");
  const titles = { graph: "Live Agent Pipeline", analytics: "Analytics", incidents: "Incident Log", scanner: "Upload Scanner" };
  document.getElementById("center-title").textContent = titles[btn.dataset.tab];
  document.getElementById("pipeline-legend").style.display = btn.dataset.tab === "graph" ? "" : "none";
});

// ============ Charts ============
let chartCategory, chartSeverity, chartAccuracy, chartMitre;
function baseOpts(extra = {}) {
  return Object.assign({
    responsive: true, maintainAspectRatio: false,
    plugins: {
      legend: { display: false },
      tooltip: { backgroundColor: "#101719", titleColor: cssVar("--bone"), bodyColor: cssVar("--bone-dim"), borderColor: cssVar("--hairline"), borderWidth: 1, padding: 8, bodyFont: { family: "IBM Plex Mono" }, titleFont: { family: "IBM Plex Mono" } },
    },
  }, extra);
}
function initCharts() {
  const grid = cssVar("--hairline"), tick = cssVar("--bone-faint");
  const fontOpts = { family: "IBM Plex Mono", size: 9.5 };
  chartCategory = new Chart(document.getElementById("chart-category"), {
    type: "bar",
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderRadius: 3, barThickness: 14 }] },
    options: baseOpts({ indexAxis: "y", scales: { x: { beginAtZero: true, ticks: { color: tick, font: fontOpts, precision: 0 }, grid: { color: grid } }, y: { ticks: { color: tick, font: fontOpts }, grid: { display: false } } } }),
  });
  chartSeverity = new Chart(document.getElementById("chart-severity"), {
    type: "doughnut",
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderColor: "#101719", borderWidth: 2 }] },
    options: baseOpts({ cutout: "62%" }),
  });
  chartAccuracy = new Chart(document.getElementById("chart-accuracy"), {
    type: "line",
    data: { labels: [], datasets: [{ data: [], borderColor: cssVar("--teal"), backgroundColor: "transparent", borderWidth: 2, pointRadius: 2.5, pointBackgroundColor: cssVar("--teal"), tension: 0.25 }] },
    options: baseOpts({ scales: { x: { ticks: { color: tick, font: fontOpts, maxRotation: 0 }, grid: { display: false } }, y: { min: 0, max: 100, ticks: { color: tick, font: fontOpts }, grid: { color: grid } } } }),
  });
  chartMitre = new Chart(document.getElementById("chart-mitre"), {
    type: "bar",
    data: { labels: [], datasets: [{ data: [], backgroundColor: [], borderRadius: 3, barThickness: 14 }] },
    options: baseOpts({ indexAxis: "y", scales: { x: { beginAtZero: true, ticks: { color: tick, font: fontOpts, precision: 0 }, grid: { color: grid } }, y: { ticks: { color: tick, font: fontOpts }, grid: { display: false } } } }),
  });
}
function renderLegend(id, entries) {
  document.getElementById(id).innerHTML = entries.map(e => `<span class="item"><span class="sw" style="background:${e.color}"></span>${esc(e.label)} (${e.value})</span>`).join("");
}
function updateCharts(incidents) {
  const catCounts = {};
  incidents.forEach(i => { const c = i.category || "Unknown"; catCounts[c] = (catCounts[c] || 0) + 1; });
  const catEntries = Object.entries(catCounts).sort((a, b) => b[1] - a[1]);
  chartCategory.data.labels = catEntries.map(e => e[0]);
  chartCategory.data.datasets[0].data = catEntries.map(e => e[1]);
  chartCategory.data.datasets[0].backgroundColor = catEntries.map(e => categoryColor(e[0]));
  chartCategory.update();
  renderLegend("legend-category", catEntries.map(([label, value]) => ({ label, value, color: categoryColor(label) })));

  const sevCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  incidents.forEach(i => { if (i.severity in sevCounts) sevCounts[i.severity]++; });
  const sevEntries = Object.entries(sevCounts).filter(([, v]) => v > 0);
  chartSeverity.data.labels = sevEntries.map(e => e[0]);
  chartSeverity.data.datasets[0].data = sevEntries.map(e => e[1]);
  chartSeverity.data.datasets[0].backgroundColor = sevEntries.map(([s]) => severityColor(s));
  chartSeverity.update();
  renderLegend("legend-severity", sevEntries.map(([label, value]) => ({ label, value, color: severityColor(label) })));

  const withScores = incidents.filter(i => typeof i.accuracy_score === "number").slice().reverse().slice(-20);
  chartAccuracy.data.labels = withScores.map(i => fmtTime(i.created_at));
  chartAccuracy.data.datasets[0].data = withScores.map(i => i.accuracy_score);
  chartAccuracy.update();

  const tacticCounts = {};
  incidents.forEach(i => { ((i.mitre_mapping && i.mitre_mapping.techniques) || []).forEach(t => { if (t.tactic) tacticCounts[t.tactic] = (tacticCounts[t.tactic] || 0) + 1; }); });
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
  document.getElementById("kpi-critical").textContent = (stats.by_severity.find(s => s.severity === "critical") || {}).c || 0;
  document.getElementById("kpi-accuracy").textContent = stats.avg_accuracy != null ? `${stats.avg_accuracy}%` : "—";
  document.getElementById("kpi-confidence").textContent = stats.avg_confidence != null ? `${stats.avg_confidence}%` : "—";
  document.getElementById("kpi-uploads").textContent = stats.uploads_blocked;
}

// ============ Incidents table ============
let incidentsCache = [];
let pinnedIncidentId = null;

function severityBadge(sev) {
  const c = severityColor(sev);
  return `<span class="badge" style="color:${c};border-color:${c}66;background:${c}1a">${esc(sev)}</span>`;
}

async function refreshIncidents() {
  incidentsCache = await fetch("/api/incidents").then(r => r.json());
  const tbody = document.getElementById("incidents-tbody");
  if (!incidentsCache.length) {
    tbody.innerHTML = `<tr><td colspan="8" class="empty-row">No incidents yet — run a simulation to begin.</td></tr>`;
  } else {
    tbody.innerHTML = incidentsCache.map(inc => `
      <tr data-id="${esc(inc.id)}" class="${inc.id === pinnedIncidentId ? "selected" : ""}">
        <td class="mono">${esc(inc.id)}</td><td>${esc(inc.attack_type)}</td><td>${esc(inc.category)}</td>
        <td>${severityBadge(inc.severity)}</td><td class="mono">${inc.accuracy_score != null ? inc.accuracy_score + "%" : "—"}</td>
        <td class="mono">${inc.confidence_score != null ? inc.confidence_score + "%" : "—"}</td>
        <td>${esc(inc.source)}</td><td class="mono">${fmtTime(inc.created_at)}</td>
      </tr>`).join("");
    tbody.querySelectorAll("tr[data-id]").forEach(tr => tr.addEventListener("click", () => {
      pinnedIncidentId = tr.dataset.id; livePinned = true;
      renderRightPanelIncident(incidentsCache.find(i => i.id === pinnedIncidentId));
      openIncidentModal(pinnedIncidentId);
      refreshIncidents();
    }));
  }
  updateCharts(incidentsCache);
}

// ============ Right panel (Current / Selected Incident) ============
function renderRightPanelEmpty(text) {
  document.getElementById("right-panel-title").textContent = "Current Incident";
  document.getElementById("right-panel-sub").textContent = "";
  document.getElementById("right-panel-body").innerHTML = `<div class="empty-state"><p>${esc(text || "No incident yet. Run a simulation, or wait — the SOC investigates on its own every couple of minutes.")}</p></div>`;
}
function readoutHtml(label, value, color) {
  return `<div class="readout sm"><div class="label">${esc(label)}</div><div class="value-row"><span class="value" style="color:${color || "var(--bone)"}">${esc(value)}</span></div></div>`;
}
function renderRightPanelLive(state) {
  document.getElementById("right-panel-title").textContent = "Current Incident";
  document.getElementById("right-panel-sub").textContent = "live";
  if (!state) { renderRightPanelEmpty(); return; }
  const analyst = state.analyst_findings || {};
  const mitre = (state.mitre_mapping && state.mitre_mapping.techniques) || [];
  document.getElementById("right-panel-body").innerHTML = `
    <div class="right-readouts">
      ${readoutHtml("Category", state.detected_category || state.category || "—")}
      ${readoutHtml("Severity", state.severity || "—", state.severity ? severityColor(state.severity) : null)}
    </div>
    ${state.accuracy ? `<div class="right-readouts" style="margin-top:6px">${readoutHtml("Accuracy", state.accuracy.accuracy_score + "%", "var(--sage)")}${readoutHtml("Confidence", (analyst.analyst_confidence ?? "—") + (analyst.analyst_confidence != null ? "%" : ""), "var(--teal)")}</div>` : ""}
    ${analyst.summary ? `<div class="right-section"><div class="head"><span class="label">Analyst</span><div class="rail tick-rail"></div></div><p>${esc(analyst.summary)}</p></div>` : ""}
    ${mitre.length ? `<div class="right-section"><div class="head"><span class="label">MITRE</span><div class="rail tick-rail"></div></div><div class="chip-row">${mitre.map(t => `<span class="badge" style="color:var(--iris);border-color:#8f8ab866;background:#8f8ab81a">${esc(t.technique_id)}</span>`).join("")}</div></div>` : ""}
  `;
}
function renderRightPanelIncident(inc) {
  if (!inc) { renderRightPanelEmpty(); return; }
  document.getElementById("right-panel-title").textContent = livePinned ? "Selected Incident" : "Current Incident";
  document.getElementById("right-panel-sub").innerHTML = livePinned ? `<a href="#" id="follow-live-link">follow live</a>` : "";
  const followLink = document.getElementById("follow-live-link");
  if (followLink) followLink.addEventListener("click", (e) => { e.preventDefault(); livePinned = false; pinnedIncidentId = null; renderRightPanelEmpty(); refreshIncidents(); });

  const analyst = inc.analyst_findings || {};
  const mitre = (inc.mitre_mapping && inc.mitre_mapping.techniques) || [];
  const plan = inc.response_plan || {};
  document.getElementById("right-panel-body").innerHTML = `
    <div class="right-readouts">
      ${readoutHtml("Accuracy", (inc.accuracy_score ?? "—") + (inc.accuracy_score != null ? "%" : ""), "var(--sage)")}
      ${readoutHtml("Confidence", (inc.confidence_score ?? "—") + (inc.confidence_score != null ? "%" : ""), "var(--teal)")}
    </div>
    <div class="right-readouts" style="margin-top:6px">
      ${readoutHtml("Severity", inc.severity || "—", severityColor(inc.severity))}
      ${readoutHtml("Priority", plan.priority || "—", "var(--amber)")}
    </div>
    ${analyst.summary ? `<div class="right-section"><div class="head"><span class="label">Why It Occurred</span><div class="rail tick-rail"></div></div><p>${esc(analyst.summary)}</p></div>` : ""}
    ${mitre.length ? `<div class="right-section"><div class="head"><span class="label">MITRE ATT&amp;CK</span><div class="rail tick-rail"></div></div><div class="chip-row">${mitre.map(t => `<span class="badge" style="color:var(--iris);border-color:#8f8ab866;background:#8f8ab81a">${esc(t.technique_id)}</span>`).join("")}</div></div>` : ""}
    <div class="right-section"><button class="btn" data-variant="primary" id="right-open-report" style="width:100%">Open Full Report</button></div>
  `;
  document.getElementById("right-open-report").addEventListener("click", () => openIncidentModal(inc.id));
}

// ============ Modal ============
let modalIncident = null;
function llmTag(backed) { return backed ? '<span class="badge" style="color:var(--teal);border-color:#6fb3ad66;background:#6fb3ad1a">LLM-generated</span>' : '<span class="badge" style="color:var(--bone-faint);border-color:#64716f66;background:#64716f1a">fallback logic</span>'; }
// title may include trusted internal HTML (e.g. an llmTag() badge span) — never pass user input here.
function sectionHtml(title, inner) { return `<div class="section"><div class="head"><span class="label engraved">${title}</span><div class="rail tick-rail"></div></div>${inner}</div>`; }

function openIncidentModal(id) {
  const inc = incidentsCache.find(i => i.id === id);
  if (!inc) return;
  modalIncident = inc;
  document.getElementById("modal-title").textContent = `${inc.id}`;
  document.getElementById("modal-sub").textContent = `${inc.attack_type} · ${inc.source}`;

  const mitre = (inc.mitre_mapping && inc.mitre_mapping.techniques) || [];
  const analyst = inc.analyst_findings || {};
  const intel = inc.threat_intel || {};
  const recon = inc.reconstruction || {};
  const rootCause = inc.root_cause || {};
  const plan = inc.response_plan || {};
  const acc = inc.accuracy || {};
  const listSection = (title, arr) => (arr && arr.length) ? sectionHtml(title, `<ul>${arr.map(a => `<li>${esc(a)}</li>`).join("")}</ul>`) : "";

  document.getElementById("modal-body").innerHTML = `
    <div class="stat-grid">
      <div class="readout"><div class="label">Accuracy</div><div class="value-row"><span class="value" style="color:var(--sage)">${inc.accuracy_score ?? "—"}</span><span class="unit">%</span></div></div>
      <div class="readout"><div class="label">Confidence</div><div class="value-row"><span class="value" style="color:var(--teal)">${inc.confidence_score ?? "—"}</span><span class="unit">%</span></div></div>
      <div class="readout"><div class="label">Severity</div><div class="value-row"><span class="value" style="color:${severityColor(inc.severity)}">${esc(inc.severity)}</span></div></div>
      <div class="readout"><div class="label">Category</div><div class="value-row"><span class="value" style="font-size:14px">${esc(inc.category)}</span></div></div>
    </div>
    <p class="mono muted" style="font-size:10px;margin-top:8px">Accuracy = 65% MITRE technique overlap (${acc.mitre_overlap_score ?? "—"}%) + 35% category match (${acc.category_match_score ?? "—"}%) vs. ground truth.</p>

    ${sectionHtml(`Detection Analyst ${llmTag(analyst.llm_backed)}`, `<p>${esc(analyst.summary || "—")}</p>${analyst.suspicious_patterns ? `<ul>${analyst.suspicious_patterns.map(p => `<li>${esc(p)}</li>`).join("")}</ul>` : ""}`)}
    ${sectionHtml(`Threat Intelligence ${llmTag(intel.llm_backed)}`, `<p>${esc(intel.likely_campaign_or_actor_profile || intel.summary || "—")}</p>${intel.ioc_context ? `<ul>${intel.ioc_context.map(p => `<li>${esc(p)}</li>`).join("")}</ul>` : ""}${intel.intel_note ? `<p class="mono muted" style="font-size:10px">${esc(intel.intel_note)}</p>` : ""}`)}
    ${sectionHtml(`Attack Reconstruction ${llmTag(recon.llm_backed)}`, `<p>${esc(recon.narrative || recon.summary || "—")}</p>${recon.timeline ? `<ul class="timeline">${recon.timeline.map(t => `<li><span class="step-num">${t.step ?? ""}</span>${esc(t.description)}</li>`).join("")}</ul>` : ""}`)}
    ${sectionHtml(`Root Cause ${llmTag(rootCause.llm_backed)}`, `<p>${esc(rootCause.root_cause || rootCause.summary || "—")}</p>${rootCause.contributing_factors ? `<ul>${rootCause.contributing_factors.map(p => `<li>${esc(p)}</li>`).join("")}</ul>` : ""}`)}
    ${sectionHtml("MITRE ATT&CK Mapping", `<div class="chip-row">${mitre.map(t => `<span class="badge" style="color:var(--iris);border-color:#8f8ab866;background:#8f8ab81a">${esc(t.technique_id)} ${esc(t.technique_name)}</span>`).join("") || '<span class="muted">No techniques mapped.</span>'}</div>`)}

    <div class="section"><div class="head"><span class="label engraved">Incident Response Plan ${llmTag(plan.llm_backed)}</span><div class="rail tick-rail"></div></div>
      ${listSection("Immediate Actions", plan.immediate_actions)}${listSection("Containment", plan.containment)}${listSection("Eradication", plan.eradication)}${listSection("Recovery", plan.recovery)}${listSection("Preventive", plan.preventive)}
    </div>

    ${sectionHtml("Raw Correlated Logs", `<div class="raw-logs">${(inc.raw_logs || []).map(esc).join("\n")}</div>`)}
    ${sectionHtml("Full Agent Trace", `<ul class="timeline">${(inc.trace || []).map(t => `<li><span class="step-num">${fmtTime(t.timestamp)}</span><strong>${esc(t.agent)}:</strong>&nbsp;${esc(t.message)}</li>`).join("")}</ul>`)}
    ${sectionHtml("Provenance", `<div class="recess provenance-grid">
      <div class="row"><span class="k">Model</span><span class="v">${esc(inc.mitre_mapping?._model_used || "—")}</span></div>
      <div class="row"><span class="k">Scenario</span><span class="v">${esc(inc.scenario_id || "—")}</span></div>
      <div class="row"><span class="k">Source</span><span class="v">${esc(inc.source)}</span></div>
      <div class="row"><span class="k">Created</span><span class="v">${esc(new Date(inc.created_at).toLocaleString())}</span></div>
    </div>`)}
  `;
  document.getElementById("modal-backdrop").classList.add("open");
}
document.getElementById("modal-close").addEventListener("click", closeModal);
document.getElementById("modal-backdrop").addEventListener("click", (e) => { if (e.target.id === "modal-backdrop") closeModal(); });
function closeModal() { document.getElementById("modal-backdrop").classList.remove("open"); }
document.getElementById("modal-export").addEventListener("click", () => {
  if (!modalIncident) return;
  const blob = new Blob([JSON.stringify(modalIncident, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = `${modalIncident.id}-report.json`;
  document.body.appendChild(a); a.click(); document.body.removeChild(a);
  URL.revokeObjectURL(url);
});

// ============ Simulate control ============
async function loadScenarios() {
  const scenarios = await fetch("/api/scenarios").then(r => r.json());
  const select = document.getElementById("scenario-select");
  scenarios.forEach(s => { const opt = document.createElement("option"); opt.value = s.id; opt.textContent = `${s.name} (${s.severity})`; select.appendChild(opt); });
}
document.getElementById("simulate-btn").addEventListener("click", async () => {
  const scenarioId = document.getElementById("scenario-select").value || null;
  const btn = document.getElementById("simulate-btn");
  btn.disabled = true; btn.textContent = "Initialising…";
  await fetch("/api/simulate", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scenario_id: scenarioId }) });
  setTimeout(() => { btn.disabled = false; btn.textContent = "Run Attack Simulation"; }, 1500);
});

// ============ Upload scanner ============
const dropzone = document.getElementById("dropzone");
const uploadInput = document.getElementById("upload-input");
dropzone.addEventListener("click", () => uploadInput.click());
dropzone.addEventListener("dragover", (e) => { e.preventDefault(); dropzone.classList.add("drag"); });
dropzone.addEventListener("dragleave", () => dropzone.classList.remove("drag"));
dropzone.addEventListener("drop", (e) => { e.preventDefault(); dropzone.classList.remove("drag"); if (e.dataTransfer.files.length) submitUpload(e.dataTransfer.files[0]); });
uploadInput.addEventListener("change", () => { if (uploadInput.files.length) submitUpload(uploadInput.files[0]); });

let lastUploadEventId = null;
async function submitUpload(file) {
  const resultEl = document.getElementById("upload-result");
  resultEl.innerHTML = `<div class="upload-verdict">Scanning "${esc(file.name)}"…</div>`;
  const form = new FormData(); form.append("file", file);
  const resp = await fetch("/api/upload", { method: "POST", body: form });
  const data = await resp.json();
  const ok = data.verdict === "accepted";
  lastUploadEventId = data.event_id;
  resultEl.innerHTML = `
    <div class="upload-verdict ${data.verdict}">
      <div class="upload-verdict-title">${ok ? "✓ Accepted" : "✗ Invalid File Type"}</div>
      <div class="mono" style="font-size:11px">Declared: <strong>.${esc(data.declared_ext || "?")}</strong> · Detected: <strong>${esc(data.detected_type || "?")}</strong></div>
      <div class="muted" style="font-size:11px;margin-top:4px">${esc(data.reason)}</div>
      ${!ok ? `<div class="mono" style="font-size:10.5px;margin-top:6px" id="upload-incident-status">Investigating via 9-agent SOC pipeline…</div>` : ""}
    </div>`;
  uploadInput.value = "";
}
function showIncidentLinkInVerdict(incidentId) {
  const statusEl = document.getElementById("upload-incident-status");
  if (!statusEl) return;
  statusEl.innerHTML = `Triggered incident <a href="#" id="jump-incident">${esc(incidentId)}</a>`;
  document.getElementById("jump-incident").addEventListener("click", async (e) => { e.preventDefault(); await refreshIncidents(); openIncidentModal(incidentId); });
}
function renderUploadHistoryItem(event) {
  const el = document.getElementById("upload-history");
  const item = document.createElement("div");
  item.className = "upload-history-item";
  item.innerHTML = `<span>${esc(event.filename)}</span><span style="color:${event.verdict === "rejected" ? "var(--terracotta)" : "var(--sage)"}">${esc(event.verdict)}</span>`;
  el.prepend(item);
  while (el.children.length > 20) el.removeChild(el.lastChild);
}
async function loadUploadHistory() {
  const events = await fetch("/api/uploads").then(r => r.json());
  document.getElementById("upload-history").innerHTML = "";
  events.forEach(renderUploadHistoryItem);
}

// ============ Init ============
async function refreshAll() { await Promise.all([refreshStats(), refreshIncidents()]); }
(async function init() {
  buildPipeline();
  initCharts();
  connectWs();
  await loadScenarios();
  await loadUploadHistory();
  await refreshAll();
})();
