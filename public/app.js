const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => [...document.querySelectorAll(selector)];

function escapeHtml(value) {
  return String(value ?? "").replace(/[&<>"']/g, (ch) => ({
    "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
  }[ch]));
}

async function api(path, options = {}) {
  const response = await fetch(path, {headers: {"Content-Type": "application/json"}, ...options});
  const data = await response.json();
  if (!response.ok || data.error) throw new Error(data.error || "Request failed");
  return data;
}

function setLoading(button, loading) {
  button.disabled = loading;
  button.dataset.originalText ||= button.textContent;
  button.textContent = loading ? "Working..." : button.dataset.originalText;
}

function item(title, body, tags = [], link) {
  const tagHtml = tags.map((tag) => `<span class="tag ${escapeHtml(tag.class || "")}">${escapeHtml(tag.text || tag)}</span>`).join("");
  const linkHtml = link ? `<a href="${escapeHtml(link)}" target="_blank" rel="noreferrer">Open source</a>` : "";
  return `<article class="item"><strong>${escapeHtml(title)}</strong><p>${escapeHtml(body)}</p><div class="row">${tagHtml}${linkHtml}</div></article>`;
}

function renderError(target, error) {
  target.innerHTML = item("Could not complete request", error.message, [{text: "check input", class: "high"}]);
}

$$(".tab").forEach((button) => {
  button.addEventListener("click", () => {
    activateTab(button.dataset.tab);
  });
});

$$(".hero-tab").forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.targetTab));
});

function activateTab(name) {
  $$(".tab").forEach((tab) => tab.classList.toggle("active", tab.dataset.tab === name));
  $$(".panel").forEach((panel) => panel.classList.toggle("active", panel.id === name));
  window.scrollTo({top: 0, behavior: "smooth"});
}

function animateScene() {
  const scene = $("#heroScene");
  const stage = $(".cyber-stage");
  if (!scene || !stage) return;
  const rect = scene.getBoundingClientRect();
  const viewport = window.innerHeight || 1;
  const progress = Math.min(1, Math.max(0, (viewport - rect.top) / (viewport + rect.height)));
  const rotateY = -12 + progress * 6;
  const lift = progress * -14;
  const scale = window.innerWidth < 820 ? 0.86 : 1;
  stage.style.transform = `rotateX(7deg) rotateY(${rotateY}deg) translateY(${lift}px) scale(${scale})`;
}

window.addEventListener("scroll", animateScene, {passive: true});
window.addEventListener("resize", animateScene);
animateScene();

async function loadThreats() {
  const button = $("#refreshThreats");
  if (button) setLoading(button, true);
  try {
    const data = await api("/api/threats");
    
    if ($("#activeAlertCount")) $("#activeAlertCount").textContent = data.kev.length;
    if ($("#highAlertCount")) $("#highAlertCount").textContent = data.advisories.length + data.maliciousUrls.length;
    
    const incidentsBody = $("#criticalIncidentsBody");
    if (incidentsBody) {
      incidentsBody.innerHTML = data.kev.slice(0, 5).map((v, index) => `
        <tr>
          <td>10${index}</td>
          <td><span class="priority-tag">Critical</span></td>
          <td>${escapeHtml(v.vulnerabilityName).slice(0, 22)}...</td>
          <td><span class="status-tag">Mitigated</span></td>
        </tr>
      `).join("");
    }
    
    const chart = $("#vulnChart");
    if (chart) {
      const low = Math.min(120, 30 + data.advisories.length * 3);
      const med = Math.min(120, 40 + data.maliciousUrls.length * 4);
      const high = Math.min(120, 50 + data.kev.length * 5);
      const crit = Math.min(120, 60 + data.kev.length * 6);
      chart.innerHTML = `
        <div class="bar-col"><div class="bar low" style="height: ${low}px;"></div><small>Low</small></div>
        <div class="bar-col"><div class="bar medium" style="height: ${med}px;"></div><small>Med</small></div>
        <div class="bar-col"><div class="bar high" style="height: ${high}px;"></div><small>High</small></div>
        <div class="bar-col"><div class="bar critical" style="height: ${crit}px;"></div><small>Crit</small></div>
      `;
    }
    
    if (data.maliciousUrls.length) {
      const first = data.maliciousUrls[0];
      if ($("#mapIpSource")) $("#mapIpSource").textContent = first.host || "198.51.100.45";
      if ($("#mapAttackType")) $("#mapAttackType").textContent = first.threat || "Malware";
    }

  } catch (error) {
    console.error("Threat feed metrics loading failed", error);
  } finally {
    if (button) setLoading(button, false);
  }
}

if ($("#refreshThreats")) {
  $("#refreshThreats").addEventListener("click", loadThreats);
}

$("#scanForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const button = event.submitter;
  const target = $("#scanResults");
  const ports = form.get("ports").split(",").map((p) => Number(p.trim())).filter(Boolean);
  setLoading(button, true);
  target.innerHTML = item("Scanning", "Checking selected ports on private/local targets only.");
  try {
    const data = await api("/api/scan", {method: "POST", body: JSON.stringify({target: form.get("target"), ports})});
    if (!data.devices.length) {
      target.innerHTML = item("No open ports found", `${data.targetCount} host(s) checked across ${data.scannedPorts.length} ports.`);
      return;
    }
    target.innerHTML = data.devices.map((device) => item(
      device.host,
      `${device.openPorts.length} open port(s) found.`,
      device.openPorts.map((port) => ({text: `${port.port}/${port.service}`, class: port.risk})),
    )).join("");
  } catch (error) {
    renderError(target, error);
  } finally {
    setLoading(button, false);
  }
});

$("#vulnForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const button = event.submitter;
  const target = $("#vulnResults");
  setLoading(button, true);
  target.innerHTML = item("Searching", "Checking NVD records and marking CISA known exploited matches.");
  try {
    const data = await api("/api/vulns", {method: "POST", body: JSON.stringify({keyword: form.get("keyword")})});
    target.innerHTML = data.items.map((v) => item(
      v.id,
      v.description,
      [
        {text: v.severity || "UNKNOWN", class: v.severity || ""},
        {text: v.score ? `CVSS ${v.score}` : "no score"},
        ...(v.knownExploited ? [{text: "known exploited", class: "high"}] : []),
      ],
      v.url,
    )).join("") || item("No CVEs found", "NVD returned 0 results for this search.");
  } catch (error) {
    renderError(target, error);
  } finally {
    setLoading(button, false);
  }
});

$("#logForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const button = event.submitter;
  const target = $("#logResults");
  setLoading(button, true);
  try {
    const data = await api("/api/logs", {method: "POST", body: JSON.stringify({logs: form.get("logs")})});
    const indicators = data.indicators.map((hit) => item(
      hit.label,
      `Seen ${hit.count} time(s). Example line ${hit.exampleLine}: ${hit.example}`,
      [{text: hit.type, class: hit.severity}],
    ));
    const ips = data.topIps.length ? item("Top IP addresses", data.topIps.map(([ip, count]) => `${ip} (${count})`).join(", ")) : "";
    target.innerHTML = indicators.join("") + ips || item("No suspicious patterns found", `${data.lineCount} line(s) reviewed.`);
  } catch (error) {
    renderError(target, error);
  } finally {
    setLoading(button, false);
  }
});

$("#phishForm").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const button = event.submitter;
  const target = $("#phishResults");
  setLoading(button, true);
  target.innerHTML = item("Checking", "Reviewing message patterns and looking up URLs in URLhaus.");
  try {
    const data = await api("/api/phishing", {method: "POST", body: JSON.stringify({text: form.get("text")})});
    const urls = data.urls.map((u) => item(
      u.host || u.url,
      u.rules.join("; "),
      [{text: u.risk, class: u.risk}, {text: u.urlhausStatus || "URLhaus checked"}],
      u.urlhausReference,
    ));
    const textFindings = data.messageFindings.map((finding) => item("Message wording indicator", finding, [{text: "social engineering", class: "medium"}]));
    target.innerHTML = [...textFindings, ...urls].join("") || item("No URL found", "Paste an email, SMS, or URL to check.");
  } catch (error) {
    renderError(target, error);
  } finally {
    setLoading(button, false);
  }
});

loadThreats();
