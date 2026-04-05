const API = "http://127.0.0.1:5000/api";

// Tab switching
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".nav-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab").forEach((t) => t.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
    if (btn.dataset.tab === "reports") loadReports();
  });
});

// Crawl toggle
const crawlToggle = document.getElementById("crawlToggle");
const externalRow = document.getElementById("externalRow");
const maxPagesGroup = document.getElementById("maxPagesGroup");
crawlToggle.addEventListener("change", () => {
  const on = crawlToggle.checked;
  externalRow.style.opacity = on ? "1" : "0.3";
  externalRow.style.pointerEvents = on ? "auto" : "none";
  maxPagesGroup.style.display = on ? "block" : "none";
});

// Max pages slider
const maxPages = document.getElementById("maxPages");
const maxPagesVal = document.getElementById("maxPagesVal");
maxPages.addEventListener("input", () => { maxPagesVal.textContent = maxPages.value; });

// Terminal helpers
const terminal = document.getElementById("terminalOutput");
function clearTerminal() {
  terminal.innerHTML = "";
}
function appendLine(text, cls = "") {
  const line = document.createElement("span");
  line.className = `t-line ${cls}`;
  line.textContent = text;
  terminal.appendChild(line);
  terminal.scrollTop = terminal.scrollHeight;
}
function classifyLine(text) {
  if (!text) return "info";
  const t = text.toLowerCase();
  if (t.includes("[!]") || t.includes("high]") || t.includes("error")) return "danger";
  if (t.includes("medium]") || t.includes("missing") || t.includes("warning")) return "warning";
  if (t.includes("[+]") || t.includes("complete") || t.includes("saved")) return "success";
  if (t.includes("[*]") || t.includes("running") || t.includes("scanning") || t.includes("crawl")) return "accent";
  if (t.includes("===") || t.includes("phase")) return "header";
  return "info";
}

document.getElementById("clearBtn").addEventListener("click", clearTerminal);

// Status dot
function setStatus(state) {
  const dot = document.querySelector(".dot");
  const statusText = document.querySelector(".status-text");
  dot.className = `dot ${state}`;
  statusText.textContent = state.toUpperCase();
}

// Scan button
const scanBtn = document.getElementById("scanBtn");
scanBtn.addEventListener("click", startScan);

async function startScan() {
  const target = document.getElementById("targetInput").value.trim();
  if (!target) {
    appendLine("⚠ Please enter a target URL.", "danger");
    return;
  }

  const modules = [...document.querySelectorAll(".module-toggle input:checked")].map((i) => i.value);
  if (!modules.length) {
    appendLine("⚠ Select at least one module.", "danger");
    return;
  }

  const payload = {
    target,
    modules,
    crawl: document.getElementById("crawlToggle").checked,
    follow_external: document.getElementById("externalToggle").checked,
    max_pages: parseInt(document.getElementById("maxPages").value),
    verbose: document.getElementById("verboseToggle").checked,
  };

  clearTerminal();
  appendLine(`[*] Target: ${target}`, "accent");
  appendLine(`[*] Modules: ${modules.join(", ")}`, "accent");
  appendLine("", "");

  scanBtn.disabled = true;
  setStatus("running");

  try {
    const res = await fetch(`${API}/scan`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const err = await res.json();
      appendLine(`✖ ${err.error || "Failed to start scan"}`, "danger");
      scanBtn.disabled = false;
      setStatus("error");
      return;
    }

    // Poll for output
    let offset = 0;
    const pollInterval = setInterval(async () => {
      try {
        const pollRes = await fetch(`${API}/scan/poll?offset=${offset}`);
        const pollData = await pollRes.json();

        pollData.lines.forEach((line) => {
          appendLine(line, classifyLine(line));
        });
        offset = pollData.offset;

        if (pollData.done) {
          clearInterval(pollInterval);
          if (pollData.error) {
            appendLine(`✖ ${pollData.error}`, "danger");
            setStatus("error");
          } else {
            appendLine("", "");
            appendLine("✔ Scan complete.", "success");
            setStatus("done");
          }
          scanBtn.disabled = false;
        }
      } catch (err) {
        clearInterval(pollInterval);
        appendLine(`✖ Lost connection to backend.`, "danger");
        scanBtn.disabled = false;
        setStatus("error");
      }
    }, 1000);
  } catch (err) {
    appendLine(`✖ Cannot connect to scanner backend. Is Flask running?`, "danger");
    appendLine(`  Error: ${err.message}`, "info");
    scanBtn.disabled = false;
    setStatus("error");
  }
}

// Reports
async function loadReports() {
  const container = document.getElementById("reportsContent");
  container.innerHTML = `<div class="empty-state">Loading...</div>`;

  try {
    const res = await fetch(`${API}/reports`);
    const data = await res.json();

    if (!data.findings || data.findings.length === 0) {
      container.innerHTML = `<div class="empty-state">No findings yet. Run a scan first.</div>`;
      return;
    }

    const counts = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    data.findings.forEach((f) => { if (counts[f.severity] !== undefined) counts[f.severity]++; });

    container.innerHTML = `
      <div class="report-meta">
        <div class="meta-item">
          <span class="meta-label">TARGET</span>
          <span class="meta-value">${data.target || "—"}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">TIMESTAMP</span>
          <span class="meta-value">${data.timestamp ? data.timestamp.replace("T", " ").replace("Z", " UTC") : "—"}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">TOTAL</span>
          <span class="meta-value">${data.findings.length} findings</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">HIGH</span>
          <span class="meta-value" style="color:var(--high)">${counts.HIGH}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">MEDIUM</span>
          <span class="meta-value" style="color:var(--medium)">${counts.MEDIUM}</span>
        </div>
        <div class="meta-item">
          <span class="meta-label">LOW</span>
          <span class="meta-value" style="color:var(--low)">${counts.LOW}</span>
        </div>
      </div>
      <div class="findings-list">
        ${data.findings
          .sort((a, b) => ["HIGH","MEDIUM","LOW","INFO"].indexOf(a.severity) - ["HIGH","MEDIUM","LOW","INFO"].indexOf(b.severity))
          .map((f) => `
            <div class="finding-card ${f.severity}">
              <div class="finding-top">
                <span class="severity-badge ${f.severity}">${f.severity}</span>
                <span class="module-badge">${f.module.toUpperCase()}</span>
                <span class="finding-title">${f.title}</span>
              </div>
              <div class="finding-detail">${f.detail}</div>
              ${f.evidence ? `<div class="finding-evidence">${f.evidence}</div>` : ""}
            </div>
          `).join("")}
      </div>
    `;
  } catch (err) {
    container.innerHTML = `<div class="empty-state">Could not load reports. Make sure Flask is running.</div>`;
  }
}

document.getElementById("refreshReports").addEventListener("click", loadReports);