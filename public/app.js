const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: options.body instanceof FormData ? {} : {"Content-Type": "application/json"},
    ...options
  });
  const data = await response.json();
  if (!response.ok || data.error) throw new Error(data.error || "Request failed");
  return data;
}

function setLoading(button, loading) {
  if (!button) return;
  button.disabled = loading;
  button.dataset.originalText ||= button.textContent;
  button.textContent = loading ? "Working..." : button.dataset.originalText;
}

function item(title, body, tags = [], link) {
  const tagHtml = tags.map((tag) => `<span class="tag ${escapeHtml(tag.class || "")}">${escapeHtml(tag.text || tag)}</span>`).join("");
  const linkHtml = link ? `<a href="${escapeHtml(link)}" target="_blank" rel="noreferrer">Open source</a>` : "";
  return `<article class="item" style="margin-bottom:12px; padding:12px; background:#111; border-radius:6px; border:1px solid #222;"><strong>${escapeHtml(title)}</strong><p style="margin:6px 0; color:#ccc;">${escapeHtml(body)}</p><div class="row" style="display:flex; gap:8px;">${tagHtml}${linkHtml}</div></article>`;
}

// Tab Switching
$$(".tab").forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.tab));
});

$$(".hero-tab").forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.targetTab));
});

function activateTab(name) {
  $$(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === name));
  $$(".panel").forEach((panel) => panel.classList.toggle("active", panel.id === name));
  window.scrollTo({top: 0, behavior: "smooth"});

  if (name === "packets") loadPackets();
  if (name === "detection") loadAlerts();
  if (name === "topology") loadTopology();
  if (name === "chain") loadChain();
  if (name === "iot") loadIoT();
  if (name === "response") loadIncidents();
}

// 1. Packet Analyzer
async function loadPackets() {
  try {
    const data = await api("/api/packets");
    if ($("#totalPacketsCount")) $("#totalPacketsCount").textContent = data.total_packets;
    if ($("#protocolBreakdown")) $("#protocolBreakdown").textContent = JSON.stringify(data.protocol_breakdown, null, 2);
    if ($("#topTalkers")) $("#topTalkers").textContent = JSON.stringify(data.top_talkers, null, 2);

    const tbody = $("#packetsTableBody");
    if (tbody && data.packets) {
      tbody.innerHTML = data.packets.map(p => `
        <tr style="border-bottom: 1px solid #222;">
          <td><b style="color:#00b0ff;">${escapeHtml(p.protocol)}</b></td>
          <td>${escapeHtml(p.src_ip || "0.0.0.0")}</td>
          <td>${escapeHtml(p.dst_ip || "0.0.0.0")}</td>
          <td>${p.src_port ? `${p.src_port} -> ${p.dst_port}` : "-"}</td>
          <td>${p.packet_size} B</td>
          <td style="color:#aaa;">${escapeHtml(p.info)}</td>
        </tr>
      `).join("");
    }
  } catch (err) {
    console.error("Failed to load packets", err);
  }
}

// PCAP Upload Handler
if ($("#btnUploadPcap")) {
  $("#btnUploadPcap").addEventListener("click", async () => {
    const fileInput = $("#pcapFileInput");
    const statusBox = $("#pcapResultStatus");
    if (!fileInput.files.length) {
      statusBox.innerHTML = "<span style='color:#ff1744;'>Please select a .pcap file first.</span>";
      return;
    }
    const file = fileInput.files[0];
    statusBox.innerHTML = "<span style='color:#00b0ff;'>Decoding PCAP file...</span>";

    try {
      const buffer = await file.arrayBuffer();
      const response = await fetch("/api/pcap/upload", {
        method: "POST",
        headers: {"Content-Type": "application/octet-stream"},
        body: buffer
      });
      const resData = await response.json();
      if (resData.error) throw new Error(resData.error);
      statusBox.innerHTML = `<span style='color:#00e676;'>Successfully parsed ${resData.total_packets} packets (${resData.total_bytes} bytes)!</span>`;
      loadPackets();
    } catch (err) {
      statusBox.innerHTML = `<span style='color:#ff1744;'>PCAP Error: ${escapeHtml(err.message)}</span>`;
    }
  });
}

// 2. Detection Engine
async function loadAlerts() {
  try {
    const alerts = await api("/api/alerts");
    if ($("#activeAlertsCount")) $("#activeAlertsCount").textContent = alerts.length;
    const container = $("#alertsContainer");
    if (container) {
      if (!alerts.length) {
        container.innerHTML = "<p style='color:#888;'>No security alerts generated yet.</p>";
        return;
      }
      container.innerHTML = alerts.map(a => item(
        `[${a.severity}] ${a.title} (${a.rule_id})`,
        `${a.description}\nEvidence: ${a.evidence}`,
        [{text: a.mitre_technique || "MITRE", class: a.severity.toLowerCase()}, {text: `${a.src_ip} -> ${a.dst_ip}`}]
      )).join("");
    }
  } catch (err) {
    console.error("Failed to load alerts", err);
  }
}

if ($("#btnRunDetection")) {
  $("#btnRunDetection").addEventListener("click", async () => {
    const btn = $("#btnRunDetection");
    setLoading(btn, true);
    try {
      const result = await api("/api/detection/run", {method: "POST", body: "{}"});
      alert(`Detection scan complete! Generated ${result.length} new alert(s).`);
      loadAlerts();
    } catch (err) {
      alert(`Detection run error: ${err.message}`);
    } finally {
      setLoading(btn, false);
    }
  });
}

// 3. Topology & OS Fingerprinting
async function loadTopology() {
  try {
    const data = await api("/api/topology");
    if ($("#topologyNodes")) $("#topologyNodes").textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    console.error("Failed to load topology", err);
  }
}

if ($("#btnRunTraceroute")) {
  $("#btnRunTraceroute").addEventListener("click", async () => {
    const btn = $("#btnRunTraceroute");
    setLoading(btn, true);
    try {
      const res = await api("/api/traceroute", {method: "POST", body: JSON.stringify({target: "8.8.8.8"})});
      if ($("#tracerouteResult")) $("#tracerouteResult").textContent = JSON.stringify(res, null, 2);
    } catch (err) {
      if ($("#tracerouteResult")) $("#tracerouteResult").textContent = err.message;
    } finally {
      setLoading(btn, false);
    }
  });
}

// 4. Audit Chain
async function loadChain() {
  try {
    const chain = await api("/api/chain");
    const tbody = $("#chainTableBody");
    if (tbody) {
      tbody.innerHTML = chain.map(b => `
        <tr style="border-bottom:1px solid #222;">
          <td><b>#${b.block_index}</b></td>
          <td>${new Date(b.timestamp * 1000).toLocaleTimeString()}</td>
          <td><code style="font-size:0.8rem;">${b.payload_hash.slice(0, 16)}...</code></td>
          <td><code style="font-size:0.8rem;">${b.prev_hash.slice(0, 16)}...</code></td>
          <td><code style="font-size:0.8rem; color:#00e676;">${b.block_hash.slice(0, 16)}...</code></td>
        </tr>
      `).join("");
    }
  } catch (err) {
    console.error("Failed to load chain", err);
  }
}

if ($("#btnVerifyChain")) {
  $("#btnVerifyChain").addEventListener("click", async () => {
    const btn = $("#btnVerifyChain");
    setLoading(btn, true);
    try {
      const res = await api("/api/chain/verify");
      const box = $("#chainVerificationBox");
      if (res.is_valid) {
        box.innerHTML = `<span style="color:#00e676;">✔ Audit Chain Verified Complete! Total Blocks: ${res.total_blocks} | Merkle Root: ${res.merkle_root.slice(0, 24)}...</span>`;
        if ($("#auditChainStatus")) $("#auditChainStatus").textContent = `VALID (${res.total_blocks} blocks)`;
      } else {
        box.innerHTML = `<span style="color:#ff1744;">✖ TAMPERING DETECTED! Broken Block Indices: [${res.broken_indices.join(", ")}]</span>`;
        if ($("#auditChainStatus")) $("#auditChainStatus").textContent = "TAMPERED";
      }
      if ($("#chainMetaBox")) $("#chainMetaBox").textContent = JSON.stringify(res, null, 2);
    } catch (err) {
      alert(`Audit verification failed: ${err.message}`);
    } finally {
      setLoading(btn, false);
    }
  });
}

// 5. IoT Monitor
async function loadIoT() {
  try {
    const data = await api("/api/iot/telemetry");
    if ($("#iotTelemetryBox")) $("#iotTelemetryBox").textContent = JSON.stringify(data, null, 2);
  } catch (err) {
    console.error("Failed to load IoT telemetry", err);
  }
}

if ($("#btnRefreshIoT")) {
  $("#btnRefreshIoT").addEventListener("click", loadIoT);
}

// 6. Incident Response
async function loadIncidents() {
  try {
    const data = await api("/api/incidents");
    const container = $("#incidentsContainer");
    if (container) {
      container.innerHTML = data.map(inc => item(
        `Incident #${inc.id}: ${inc.title}`,
        `Status: ${inc.status} | Assigned: ${inc.assigned_to}\nNotes: ${inc.notes}`,
        [{text: inc.severity, class: inc.severity.toLowerCase()}]
      )).join("");
    }
  } catch (err) {
    console.error("Failed to load incidents", err);
  }
}

// 7. Live consolidated audit summary (web audit JSON)
if ($("#btnLoadAuditSummary")) {
  $("#btnLoadAuditSummary").addEventListener("click", async () => {
    const btn = $("#btnLoadAuditSummary");
    setLoading(btn, true);
    try {
      const data = await api("/api/audit/report");
      if ($("#auditSummaryBox")) {
        const summary = {
          generated_at: data.generated_at,
          totals: data.totals,
          severity_counts: data.severity_counts,
          rule_counts: data.rule_counts,
          verification: data.verification,
        };
        $("#auditSummaryBox").textContent = JSON.stringify(summary, null, 2);
      }
    } catch (err) {
      if ($("#auditSummaryBox")) $("#auditSummaryBox").textContent = `Audit load failed: ${err.message}`;
    } finally {
      setLoading(btn, false);
    }
  });
}

// Existing Action Handlers
if ($("#btnScan")) {
  $("#btnScan").addEventListener("click", async () => {
    const targetVal = $("#scanTarget").value;
    const btn = $("#btnScan");
    setLoading(btn, true);
    try {
      const data = await api("/api/scan", {method: "POST", body: JSON.stringify({target: targetVal, ports: [21, 22, 23, 80, 443, 8080]})});
      if ($("#scanResults")) $("#scanResults").textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      if ($("#scanResults")) $("#scanResults").textContent = err.message;
    } finally {
      setLoading(btn, false);
    }
  });
}

if ($("#btnVuln")) {
  $("#btnVuln").addEventListener("click", async () => {
    const query = $("#vulnQuery").value;
    const btn = $("#btnVuln");
    setLoading(btn, true);
    try {
      const data = await api("/api/vulns", {method: "POST", body: JSON.stringify({keyword: query})});
      if ($("#vulnResults")) $("#vulnResults").textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      if ($("#vulnResults")) $("#vulnResults").textContent = err.message;
    } finally {
      setLoading(btn, false);
    }
  });
}

if ($("#btnAnalyzeLogs")) {
  $("#btnAnalyzeLogs").addEventListener("click", async () => {
    const logs = $("#logInput").value;
    const btn = $("#btnAnalyzeLogs");
    setLoading(btn, true);
    try {
      const data = await api("/api/logs", {method: "POST", body: JSON.stringify({logs})});
      if ($("#logResults")) $("#logResults").textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      if ($("#logResults")) $("#logResults").textContent = err.message;
    } finally {
      setLoading(btn, false);
    }
  });
}

if ($("#btnCheckPhish")) {
  $("#btnCheckPhish").addEventListener("click", async () => {
    const text = $("#phishInput").value;
    const btn = $("#btnCheckPhish");
    setLoading(btn, true);
    try {
      const data = await api("/api/phishing", {method: "POST", body: JSON.stringify({text})});
      if ($("#phishResults")) $("#phishResults").textContent = JSON.stringify(data, null, 2);
    } catch (err) {
      if ($("#phishResults")) $("#phishResults").textContent = err.message;
    } finally {
      setLoading(btn, false);
    }
  });
}

// Initial overview loads
loadPackets();
loadAlerts();
