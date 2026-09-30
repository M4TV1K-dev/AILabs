// State
let currentTask = null;
let pollingInterval = null;
let selectedProfile = "aggressive";

document.addEventListener("DOMContentLoaded", () => {
  initApp();
  setupEventListeners();
});

async function initApp() {
  await loadProfiles();
  await loadConfig();
  await loadTasks();
  checkLLMStatus();
  setInterval(checkLLMStatus, 8000);
}

function setupEventListeners() {
  // Target Input Validation
  const targetInput = document.getElementById("target-input");
  targetInput.addEventListener("input", (e) => {
    validateTargetLive(e.target.value);
  });

  // Start Scan
  document.getElementById("btn-start-scan").addEventListener("click", () => {
    startScan(false);
  });

  // Demo Scan (from PDF scenario)
  document.getElementById("btn-start-demo").addEventListener("click", () => {
    startScan(true);
  });

  // Settings Modal
  document.getElementById("btn-open-settings").addEventListener("click", () => {
    openSettingsModal();
  });
  document.getElementById("btn-close-settings").addEventListener("click", () => {
    closeSettingsModal();
  });
  document.getElementById("btn-save-settings").addEventListener("click", saveSettings);
  document.getElementById("btn-test-llm").addEventListener("click", testLLMConnection);

  // Tabs switching
  document.querySelectorAll(".tab-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
      document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));

      btn.classList.add("active");
      const targetId = btn.getAttribute("data-tab");
      document.getElementById(targetId).classList.add("active");
    });
  });

  // Report actions
  document.getElementById("btn-download-md").addEventListener("click", downloadReport);
  document.getElementById("btn-reanalyze").addEventListener("click", reanalyzeTask);
  document.getElementById("btn-print").addEventListener("click", () => window.print());
  document.getElementById("btn-copy-json").addEventListener("click", copyJSONManifest);
}

// Load available profiles from Go backend
async function loadProfiles() {
  try {
    const res = await fetch("/api/profiles");
    const profiles = await res.json();
    const container = document.getElementById("profiles-container");
    container.innerHTML = "";

    profiles.forEach((p) => {
      const card = document.createElement("div");
      card.className = `profile-card ${p.id === selectedProfile ? "active" : ""}`;
      card.onclick = () => selectProfile(p.id);
      card.innerHTML = `
        <div class="profile-card-header">
          <span>${p.name}</span>
          <span class="profile-badge">${p.id}</span>
        </div>
        <div class="profile-desc">${p.description}</div>
      `;
      container.appendChild(card);
    });
  } catch (err) {
    console.error("Failed to load profiles:", err);
  }
}

function selectProfile(profileId) {
  selectedProfile = profileId;
  document.querySelectorAll(".profile-card").forEach((c) => {
    if (c.innerHTML.includes(profileId)) {
      c.classList.add("active");
    } else {
      c.classList.remove("active");
    }
  });
}

function validateTargetLive(val) {
  const feedback = document.getElementById("target-feedback");
  val = val.trim();
  if (!val) {
    feedback.innerText = "Укажите IP (192.168.1.1), CIDR (192.168.1.0/24) или домен";
    feedback.style.color = "var(--text-dim)";
    return false;
  }
  // Basic validation check
  const ipPattern = /^(\d{1,3}\.){3}\d{1,3}(\/\d{1,2})?$/;
  const domainPattern = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  if (ipPattern.test(val) || domainPattern.test(val) || val === "localhost") {
    feedback.innerText = "✓ Корректный формат цели";
    feedback.style.color = "var(--risk-green)";
    return true;
  } else {
    feedback.innerText = "⚠ Проверьте формат цели (IP/домен)";
    feedback.style.color = "var(--risk-yellow)";
    return false;
  }
}

// Start Audit Task
async function startScan(isDemo) {
  let target = document.getElementById("target-input").value.trim();
  if (isDemo) {
    target = "192.168.10.15";
    document.getElementById("target-input").value = target;
  }

  if (!target) {
    alert("Пожалуйста, укажите цель сканирования!");
    return;
  }

  const isExpress = document.getElementById("mode-express") && document.getElementById("mode-express").checked;

  const payload = {
    target: target,
    profile_id: selectedProfile,
    is_demo: isDemo,
    no_llm: isExpress,
  };

  try {
    const res = await fetch("/api/tasks", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    if (!res.ok) {
      const errData = await res.json();
      alert("Ошибка запуска аудита: " + (errData.error || res.statusText));
      return;
    }

    const task = await res.json();
    currentTask = task;
    switchViewToTask(task);
    startPolling(task.id);
    loadTasks();
  } catch (err) {
    alert("Ошибка соединения с бэкендом: " + err.message);
  }
}

function startPolling(taskId) {
  if (pollingInterval) clearInterval(pollingInterval);
  pollingInterval = setInterval(async () => {
    try {
      const res = await fetch(`/api/tasks/${taskId}`);
      if (!res.ok) return;
      const task = await res.json();
      currentTask = task;
      updateTaskUI(task);

      if (task.status === "completed" || task.status === "failed") {
        clearInterval(pollingInterval);
        pollingInterval = null;
        loadTasks();
      }
    } catch (e) {
      console.error("Polling error:", e);
    }
  }, 900);
}

function updateTaskUI(task) {
  // Update Stepper
  updateStepper(task.status);

  // Update Logs Terminal
  const terminal = document.getElementById("terminal-logs");
  if (task.logs && task.logs.length) {
    terminal.innerText = task.logs.join("\n");
    terminal.scrollTop = terminal.scrollHeight;
  }

  // If currently analyzing in LLM, show live progress
  if (task.status === "analyzing_llm") {
    const reportElem = document.getElementById("report-content");
    reportElem.innerHTML = `
      <div style="text-align:center; padding: 2.5rem 1rem; color: var(--accent-blue);">
        <div style="font-size: 2.5rem; margin-bottom: 0.75rem; animation: pulse 1.5s infinite;">🧠</div>
        <h3 style="color:#fff;">Локальная нейросеть анализирует скан...</h3>
        <p style="color: var(--text-muted); font-size: 0.85rem; margin-top: 0.5rem; max-width: 500px; margin-left: auto; margin-right: auto;">
          Модель изучает порты, версии и CVE, формируя отчет для директора. Генерация на локальном железе занимает 1–2 минуты, дождитесь завершения.
        </p>
      </div>
    `;
  }

  // If completed, update metrics and content tabs
  if (task.status === "completed" && task.manifest) {
    document.getElementById("metric-target").innerText = task.manifest.target_metadata.ip || task.target;
    document.getElementById("metric-os").innerText = task.manifest.target_metadata.os_detected || "Не определена";
    document.getElementById("metric-ports").innerText = task.manifest.open_services.length;

    let cveCount = 0;
    task.manifest.open_services.forEach((s) => {
      if (s.reported_cves) cveCount += s.reported_cves.length;
    });
    document.getElementById("metric-cves").innerText = cveCount;
    document.getElementById("metric-duration").innerText = task.duration || "-";

    // Render LLM Markdown Report
    const reportElem = document.getElementById("report-content");
    reportElem.innerHTML = renderMarkdown(task.llm_report || "Отчет формируется...");

    // Render Services Table
    renderServicesTable(task.manifest.open_services);

    // Render JSON Manifest
    document.getElementById("json-manifest").innerText = JSON.stringify(task.manifest, null, 2);

    // Render Raw XML
    document.getElementById("raw-xml-content").innerText = task.raw_xml || "(Сырой XML не сохранен)";
  }
}

function updateStepper(status) {
  const steps = ["step-scan", "step-norm", "step-llm", "step-report"];
  steps.forEach((s) => {
    const el = document.getElementById(s);
    el.classList.remove("active", "done");
  });

  if (status === "scanning") {
    document.getElementById("step-scan").classList.add("active");
  } else if (status === "normalizing") {
    document.getElementById("step-scan").classList.add("done");
    document.getElementById("step-norm").classList.add("active");
  } else if (status === "analyzing_llm") {
    document.getElementById("step-scan").classList.add("done");
    document.getElementById("step-norm").classList.add("done");
    document.getElementById("step-llm").classList.add("active");
  } else if (status === "completed") {
    steps.forEach((s) => document.getElementById(s).classList.add("done"));
  }
}

function renderServicesTable(services) {
  const tbody = document.getElementById("services-tbody");
  tbody.innerHTML = "";

  if (!services || !services.length) {
    tbody.innerHTML = `<tr><td colspan="5" style="text-align:center; color:var(--text-dim);">Открытых портов не обнаружено</td></tr>`;
    return;
  }

  services.forEach((s) => {
    let cveBadges = "";
    if (s.reported_cves && s.reported_cves.length > 0) {
      s.reported_cves.forEach((c) => {
        const cls = c.cvss >= 7.5 ? "critical" : "high";
        cveBadges += `<span class="cve-badge ${cls}" title="${c.type}">${c.id} (CVSS ${c.cvss})</span>`;
      });
    } else {
      cveBadges = `<span style="color:var(--text-dim); font-size:0.75rem;">Уязвимостей не выявлено</span>`;
    }

    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td><strong>${s.port}</strong>/${s.protocol}</td>
      <td><code>${s.service}</code></td>
      <td>${s.product || "-"}</td>
      <td>${s.version || "-"}</td>
      <td>${cveBadges}</td>
    `;
    tbody.appendChild(tr);
  });
}

// Simple fast markdown parser to render headings, bold, bullet lists, badges
function renderMarkdown(md) {
  if (!md) return "";
  let html = md
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  // Code blocks
  html = html.replace(/```([\s\S]*?)```/g, "<pre><code>$1</code></pre>");

  // Headings
  html = html.replace(/^#### (.*$)/gim, "<h4 style='color:#e2e8f0; margin-top:1rem; font-size:0.95rem;'>$1</h4>");
  html = html.replace(/^### (.*$)/gim, "<h3 style='color:#38bdf8; margin-top:1.25rem; font-size:1.1rem; border-bottom:1px solid var(--border-color); padding-bottom:0.3rem;'>$1</h3>");
  html = html.replace(/^## (.*$)/gim, "<h2 style='color:#fff; margin-top:1.5rem; font-size:1.25rem;'>$1</h2>");
  html = html.replace(/^# (.*$)/gim, "<h1 style='color:#fff; font-size:1.45rem; border-bottom:2px solid var(--accent-blue); padding-bottom:0.5rem;'>$1</h1>");

  // Blockquotes (styled callout box)
  html = html.replace(/^\> (.*$)/gim, "<blockquote>$1</blockquote>");

  // Restore details and summary tags
  html = html.replace(/&lt;details&gt;/g, "<details style='margin-top:1.5rem; background:rgba(0,0,0,0.25); border:1px dashed var(--border-color); border-radius:6px; padding:0.75rem;'>");
  html = html.replace(/&lt;\/details&gt;/g, "</details>");
  html = html.replace(/&lt;summary&gt;(.*?)&lt;\/summary&gt;/g, "<summary style='cursor:pointer; font-weight:600; color:var(--text-muted); outline:none;'>$1</summary>");

  // Tables
  html = html.replace(/\n\|(.+)\|\n\|[-:| ]+\|\n((?:\|.*\|\n?)+)/g, (match, header, rows) => {
    const ths = header.split('|').filter(c => c.trim()).map(c => `<th style="padding:0.6rem 0.8rem; border-bottom:1px solid var(--border-color); text-align:left; background:var(--bg-card); font-size:0.8rem;">${c.trim()}</th>`).join('');
    const trs = rows.trim().split('\n').map(row => {
      const tds = row.split('|').filter(c => c.trim()).map(c => `<td style="padding:0.5rem 0.8rem; border-bottom:1px solid var(--border-color); font-size:0.85rem;">${c.trim()}</td>`).join('');
      return `<tr>${tds}</tr>`;
    }).join('');
    return `<div style="overflow-x:auto; margin:1rem 0;"><table style="width:100%; border-collapse:collapse; border:1px solid var(--border-color); border-radius:6px; overflow:hidden;"><thead><tr>${ths}</tr></thead><tbody>${trs}</tbody></table></div>`;
  });

  // Bold & Italic
  html = html.replace(/\*\*(.*?)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\*(.*?)\*/g, "<em>$1</em>");
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");

  // Horizontal rules
  html = html.replace(/^---$/gim, "<hr style='border:0; border-top:1px solid var(--border-color); margin:1.25rem 0;' />");

  // Lists
  html = html.replace(/^\- (.*$)/gim, "<li>$1</li>");
  html = html.replace(/(<li>.*<\/li>)/s, "<ul>$1</ul>");

  // Line breaks
  html = html.replace(/\n\n/g, "<br/>");

  return html;
}

// Load Task History
async function loadTasks() {
  try {
    const res = await fetch("/api/tasks");
    const tasks = await res.json();
    const list = document.getElementById("tasks-history-list");
    list.innerHTML = "";

    if (!tasks.length) {
      list.innerHTML = `<div style="padding:0.5rem; color:var(--text-dim); font-size:0.75rem;">История сканирований пуста</div>`;
      return;
    }

    tasks.forEach((t) => {
      const item = document.createElement("div");
      item.className = `task-item ${currentTask && currentTask.id === t.id ? "active" : ""}`;
      item.onclick = () => {
        currentTask = t;
        switchViewToTask(t);
        updateTaskUI(t);
        if (t.status !== "completed" && t.status !== "failed") {
          startPolling(t.id);
        }
      };

      let badgeColor = "var(--text-dim)";
      if (t.status === "completed") badgeColor = "var(--risk-green)";
      else if (t.status === "failed") badgeColor = "var(--risk-red)";
      else badgeColor = "var(--accent-blue)";

      item.innerHTML = `
        <div>
          <div><strong>${t.target}</strong> ${t.is_demo ? "<em>(демо)</em>" : ""}</div>
          <div style="font-size:0.7rem; color:var(--text-dim);">${new Date(t.created_at).toLocaleTimeString()}</div>
        </div>
        <div style="color:${badgeColor}; font-weight:600; font-size:0.75rem;">${t.status}</div>
      `;
      list.appendChild(item);
    });

    // Auto-select latest task on page load if none selected
    if (!currentTask && tasks.length > 0) {
      currentTask = tasks[0];
      switchViewToTask(currentTask);
      updateTaskUI(currentTask);
      if (currentTask.status !== "completed" && currentTask.status !== "failed") {
        startPolling(currentTask.id);
      }
    }
  } catch (err) {
    console.error("Tasks load failed:", err);
  }
}

function switchViewToTask(task) {
  updateTaskUI(task);
}

// Download markdown report
function downloadReport() {
  if (!currentTask) return;
  window.location.href = `/api/tasks/${currentTask.id}/download`;
}

// Reanalyze existing task with LLM
async function reanalyzeTask() {
  if (!currentTask) return;
  try {
    const res = await fetch(`/api/tasks/${currentTask.id}/reanalyze`, { method: "POST" });
    if (res.ok) {
      startPolling(currentTask.id);
    }
  } catch (err) {
    alert("Ошибка запуска анализа: " + err.message);
  }
}

function copyJSONManifest() {
  const jsonText = document.getElementById("json-manifest").innerText;
  navigator.clipboard.writeText(jsonText).then(() => {
    alert("JSON-манифест успешно скопирован в буфер обмена!");
  });
}

// Config & Settings
async function loadConfig() {
  try {
    const res = await fetch("/api/config");
    const cfg = await res.json();
    document.getElementById("cfg-provider").value = cfg.llm.provider || "openai";
    document.getElementById("cfg-endpoint").value = cfg.llm.endpoint || "http://127.0.0.1:5000/v1";
    document.getElementById("cfg-model").value = cfg.llm.model || "qwen2.5";
    document.getElementById("cfg-temp").value = cfg.llm.temperature || 0.2;
    document.getElementById("cfg-nmap-path").value = cfg.nmap_path || "nmap";

    document.getElementById("status-llm-label").innerText = `LLM: ${cfg.llm.model}`;
  } catch (e) {
    console.error("Config load error:", e);
  }
}

function openSettingsModal() {
  document.getElementById("settings-modal").classList.add("active");
}

function closeSettingsModal() {
  document.getElementById("settings-modal").classList.remove("active");
}

async function saveSettings() {
  const payload = {
    server_port: ":8080",
    nmap_path: document.getElementById("cfg-nmap-path").value.trim(),
    llm: {
      provider: document.getElementById("cfg-provider").value,
      endpoint: document.getElementById("cfg-endpoint").value.trim(),
      model: document.getElementById("cfg-model").value.trim(),
      temperature: parseFloat(document.getElementById("cfg-temp").value) || 0.2,
      max_tokens: 2500,
      api_key: document.getElementById("cfg-key").value.trim(),
    },
  };

  try {
    const res = await fetch("/api/config", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });
    if (res.ok) {
      closeSettingsModal();
      checkLLMStatus();
      loadConfig();
      alert("Настройки успешно сохранены!");
    } else {
      alert("Ошибка сохранения настроек");
    }
  } catch (e) {
    alert("Ошибка: " + e.message);
  }
}

async function testLLMConnection() {
  const feedback = document.getElementById("test-feedback");
  feedback.innerText = "Проверка соединения...";
  feedback.style.color = "var(--accent-blue)";

  try {
    const res = await fetch("/api/llm/test", { method: "POST" });
    const data = await res.json();
    if (res.ok) {
      feedback.innerText = "✓ Подключение к TextGen/LLM успешно!";
      feedback.style.color = "var(--risk-green)";
    } else {
      feedback.innerText = "✗ " + (data.error || "Ошибка подключения");
      feedback.style.color = "var(--risk-red)";
    }
  } catch (e) {
    feedback.innerText = "✗ Ошибка сети: " + e.message;
    feedback.style.color = "var(--risk-red)";
  }
}

async function checkLLMStatus() {
  const dot = document.getElementById("dot-llm");
  try {
    const res = await fetch("/api/llm/test", { method: "POST" });
    if (res.ok) {
      dot.className = "dot online";
    } else {
      dot.className = "dot warn";
    }
  } catch (e) {
    dot.className = "dot warn";
  }
}
