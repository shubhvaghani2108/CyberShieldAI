/* =========================================================
   CyberShieldAI — Dashboard interactivity
   Sidebar toggle, live clock, particles, scan modal, charts
   ========================================================= */

document.addEventListener("DOMContentLoaded", function () {
  initSidebarToggle();
  initClock();
  initScanModal();
  initCharts();
  initThemeToggle();
  initUtcToLocalTimestamps();
});

/* ---------------- theme toggle (dark / light / system) ---------------- */
function initThemeToggle() {
  const root = document.documentElement;
  let stored = localStorage.getItem("csa-theme");
  
  if (!stored) {
    const match = document.cookie.match(new RegExp("(?:^|; )csa_theme=([^;]*)"));
    if (match) stored = decodeURIComponent(match[1]);
  }

  if (!stored) {
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches) {
      stored = "light";
    } else {
      stored = "dark";
    }
  }

  if (stored === "light") {
    root.setAttribute("data-theme", "light");
  } else {
    root.setAttribute("data-theme", "dark");
  }

  const toggle = document.querySelector("[data-theme-toggle]");
  if (!toggle) return;

  function syncUI() {
    const isLight = root.getAttribute("data-theme") === "light";
    toggle.setAttribute("aria-pressed", isLight ? "true" : "false");
    const label = toggle.querySelector(".theme-toggle-label");
    if (label) label.textContent = isLight ? "Light" : "Dark";

    const sunIcon = toggle.querySelector(".theme-icon-sun");
    const moonIcon = toggle.querySelector(".theme-icon-moon");
    if (sunIcon && moonIcon) {
      sunIcon.style.display = isLight ? "inline-block" : "none";
      moonIcon.style.display = isLight ? "none" : "inline-block";
    }
  }
  syncUI();

  // Listen for real-time OS theme switches if user has not manually overridden theme
  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", (e) => {
      if (!localStorage.getItem("csa-theme")) {
        const theme = e.matches ? "light" : "dark";
        root.setAttribute("data-theme", theme);
        syncUI();
        if (typeof updateChartsTheme === "function") {
          updateChartsTheme();
        }
      }
    });
  }

  toggle.addEventListener("click", () => {
    const isLight = root.getAttribute("data-theme") === "light";
    const nextTheme = isLight ? "dark" : "light";
    
    root.setAttribute("data-theme", nextTheme);
    localStorage.setItem("csa-theme", nextTheme);
    document.cookie = "csa_theme=" + nextTheme + "; path=/; max-age=31536000; SameSite=Lax";
    
    syncUI();
    if (typeof updateChartsTheme === "function") {
      updateChartsTheme();
    }
  });
}

/* ---------------- particles ---------------- */
/* ---------------- sidebar (slide panel) ---------------- */
function initSidebarToggle() {
  const toggle = document.querySelector(".sidebar-toggle");
  const sidebar = document.querySelector(".sidebar");
  const backdrop = document.getElementById("sidebarBackdrop");
  const closeBtn = document.querySelector("[data-close-sidebar]");
  if (!toggle || !sidebar) return;

  function openSidebar() {
    sidebar.classList.add("open");
    if (backdrop) backdrop.classList.add("open");
    toggle.setAttribute("aria-expanded", "true");
  }
  function closeSidebar() {
    sidebar.classList.remove("open");
    if (backdrop) backdrop.classList.remove("open");
    toggle.setAttribute("aria-expanded", "false");
  }

  toggle.addEventListener("click", () => {
    sidebar.classList.contains("open") ? closeSidebar() : openSidebar();
  });
  if (closeBtn) closeBtn.addEventListener("click", closeSidebar);
  if (backdrop) backdrop.addEventListener("click", closeSidebar);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && sidebar.classList.contains("open")) closeSidebar();
  });
  // Close automatically once a nav link is used, so the panel doesn't
  // stay open over the newly-loaded page.
  sidebar.querySelectorAll(".sidebar-nav a").forEach((link) => {
    link.addEventListener("click", closeSidebar);
  });
}

/* ---------------- live clock ---------------- */
function initClock() {
  const el = document.querySelector(".topbar-clock");
  if (!el) return;
  function tick() {
    const now = new Date();
    el.textContent = now.toLocaleString(undefined, {
      weekday: "short",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  }
  tick();
  setInterval(tick, 1000);
}

/* ---------------- new scan modal ---------------- */
function initScanModal() {
  const overlay = document.getElementById("newScanModal");
  const openBtns = document.querySelectorAll("[data-open-scan-modal]");
  const closeBtns = document.querySelectorAll("[data-close-scan-modal]");
  if (!overlay) return;

  openBtns.forEach((btn) =>
    btn.addEventListener("click", () => overlay.classList.add("open"))
  );
  closeBtns.forEach((btn) =>
    btn.addEventListener("click", () => overlay.classList.remove("open"))
  );
  overlay.addEventListener("click", (e) => {
    if (e.target === overlay) overlay.classList.remove("open");
  });

  // Disable + relabel the submit button on whichever form is submitted,
  // so a double-click can't fire two scan jobs.
  document.querySelectorAll(".scan-form").forEach((form) => {
    form.addEventListener("submit", () => {
      const submitBtn = form.querySelector('button[type="submit"]');
      if (submitBtn) {
        submitBtn.disabled = true;
        submitBtn.textContent = "Launching scan...";
      }
    });
  });

  // Tab switching between "IP Scan" and "URL Scan".
  const tabs = document.querySelectorAll("[data-scan-tab]");
  const forms = document.querySelectorAll("[data-scan-form]");
  const subtitle = document.getElementById("scanModalSub");
  const subtitles = {
    ip: "Scan an IP address for open ports, running services, and network vulnerabilities.",
    url: "Scan a website URL for web threats, SSL/TLS certificates, DNS records, and vulnerabilities.",
  };

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      const target = tab.getAttribute("data-scan-tab");

      tabs.forEach((t) => {
        const active = t === tab;
        t.classList.toggle("active", active);
        t.setAttribute("aria-selected", active ? "true" : "false");
      });

      forms.forEach((f) => {
        f.style.display = f.getAttribute("data-scan-form") === target ? "" : "none";
      });

      if (subtitle && subtitles[target]) {
        subtitle.textContent = subtitles[target];
      }
    });
  });
}

/* ---------------- toast helper (used by other pages too) ---------------- */
function showToast(message) {
  let stack = document.querySelector(".toast-stack");
  if (!stack) {
    stack = document.createElement("div");
    stack.className = "toast-stack";
    document.body.appendChild(stack);
  }
  const toast = document.createElement("div");
  toast.className = "toast";
  toast.textContent = message;
  stack.appendChild(toast);
  setTimeout(() => toast.remove(), 4000);
}

/* ---------------- charts ---------------- */
const activeChartInstances = [];

function getChartThemeColors() {
  const isLight = document.documentElement.getAttribute("data-theme") === "light";
  return {
    textColor: isLight ? "#475569" : "#aab4d4",
    gridColor: isLight ? "rgba(15,23,42,0.08)" : "rgba(122,162,255,0.08)",
    doughnutBorder: isLight ? "#ffffff" : "#12151c"
  };
}

function updateChartsTheme() {
  if (typeof Chart === "undefined" || activeChartInstances.length === 0) return;
  const colors = getChartThemeColors();
  Chart.defaults.color = colors.textColor;

  activeChartInstances.forEach((chart) => {
    if (!chart || !chart.options) return;
    if (chart.config.type === "doughnut" && chart.data && chart.data.datasets && chart.data.datasets[0]) {
      chart.data.datasets[0].borderColor = colors.doughnutBorder;
    }
    if (chart.options.scales) {
      if (chart.options.scales.x && chart.options.scales.x.grid) {
        chart.options.scales.x.grid.color = colors.gridColor;
      }
      if (chart.options.scales.y && chart.options.scales.y.grid) {
        chart.options.scales.y.grid.color = colors.gridColor;
      }
    }
    chart.update();
  });
}

function initCharts() {
  const dataEl = document.getElementById("dashboard-data");
  if (!dataEl || typeof Chart === "undefined") return;

  let data;
  try {
    data = JSON.parse(dataEl.textContent);
  } catch (e) {
    console.error("CyberShieldAI: could not parse dashboard data", e);
    return;
  }

  const colors = getChartThemeColors();
  Chart.defaults.color = colors.textColor;
  Chart.defaults.font.family = "Inter, system-ui, sans-serif";
  Chart.defaults.font.size = 11;

  /* -------- Severity distribution (doughnut) -------- */
  const sevCanvas = document.getElementById("severityChart");
  if (sevCanvas) {
    const sev = data.severity || { critical: 0, high: 0, medium: 0, low: 0 };
    const total = sev.critical + sev.high + sev.medium + sev.low;
    if (total > 0) {
      const chart = new Chart(sevCanvas, {
        type: "doughnut",
        data: {
          labels: ["Critical", "High", "Medium", "Low"],
          datasets: [
            {
              data: [sev.critical, sev.high, sev.medium, sev.low],
              backgroundColor: ["#ff3b6b", "#ff9f43", "#ffd93d", "#4fd1c5"],
              borderColor: colors.doughnutBorder,
              borderWidth: 3,
              hoverOffset: 6,
            },
          ],
        },
        options: {
          maintainAspectRatio: false,
          cutout: "68%",
          plugins: {
            legend: {
              position: "bottom",
              labels: { boxWidth: 10, boxHeight: 10, padding: 14 },
            },
          },
        },
      });
      activeChartInstances.push(chart);
    } else {
      sevCanvas.replaceWith(emptyState("No vulnerability data yet — run a scan to populate this chart."));
    }
  }

  /* -------- Port / service distribution (bar) -------- */
  const portCanvas = document.getElementById("portChart");
  if (portCanvas) {
    const ports = data.port_distribution || [];
    if (ports.length > 0) {
      const chart = new Chart(portCanvas, {
        type: "bar",
        data: {
          labels: ports.map((p) => p.label),
          datasets: [
            {
              label: "Open ports",
              data: ports.map((p) => p.count),
              backgroundColor: "rgba(58,214,255,0.55)",
              hoverBackgroundColor: "rgba(58,214,255,0.85)",
              borderRadius: 6,
              maxBarThickness: 28,
            },
          ],
        },
        options: {
          maintainAspectRatio: false,
          plugins: { legend: { display: false } },
          scales: {
            x: { grid: { display: false } },
            y: {
              beginAtZero: true,
              ticks: { precision: 0 },
              grid: { color: colors.gridColor },
            },
          },
        },
      });
      activeChartInstances.push(chart);
    } else {
      portCanvas.replaceWith(emptyState("No open ports detected yet — run a scan to populate this chart."));
    }
  }

  /* -------- Risk trend across recent scans (line) -------- */
  const riskCanvas = document.getElementById("riskTrendChart");
  if (riskCanvas) {
    const trend = data.risk_trend || [];
    if (trend.length > 0) {
      const chart = new Chart(riskCanvas, {
        type: "line",
        data: {
          labels: trend.map((t) => t.label),
          datasets: [
            {
              label: "Risk Score",
              data: trend.map((t) => t.score),
              borderColor: "#a45bff",
              backgroundColor: "rgba(164,91,255,0.15)",
              fill: true,
              tension: 0.35,
              pointRadius: 5,
              pointHoverRadius: 8,
              pointHitRadius: 12,
              pointBackgroundColor: "#a45bff",
              pointBorderColor: "#ffffff",
              pointBorderWidth: 1.5,
            },
          ],
        },
        options: {
          maintainAspectRatio: false,
          plugins: {
            legend: { display: false },
            tooltip: {
              callbacks: {
                label: function (context) {
                  return `Risk Score: ${context.parsed.y} / 100`;
                },
              },
            },
          },
          scales: {
            x: { grid: { display: false } },
            y: {
              min: 0,
              suggestedMax: 100,
              grid: { color: colors.gridColor },
              ticks: {
                stepSize: 20,
                callback: function (value) {
                  return value;
                },
              },
            },
          },
        },
      });
      activeChartInstances.push(chart);
    } else {
      riskCanvas.replaceWith(emptyState("No historical scans yet — risk trend appears after multiple scans."));
    }
  }
}

function emptyState(message) {
  const div = document.createElement("div");
  div.className = "chart-empty";
  div.innerHTML = `<span>📉</span><span>${message}</span>`;
  return div;
}

/* ---------------- UTC to Local Timezone Universal Auto-Converter ---------------- */
function initUtcToLocalTimestamps() {
  function formatUtcTimestamp(utcStr) {
    if (!utcStr || typeof utcStr !== "string") return null;
    const trimmed = utcStr.trim();
    if (trimmed === "Never" || trimmed === "None" || trimmed === "-" || trimmed === "—") return null;

    // Match YYYY-MM-DD HH:MM:SS or YYYY-MM-DDTHH:MM:SS
    const match = trimmed.match(/^(\d{4})-(\d{2})-(\d{2})[T\s](\d{2}):(\d{2}):(\d{2})/);
    if (!match) return null;

    const [_, y, m, d, h, min, s] = match;
    const utcDate = new Date(Date.UTC(+y, +m - 1, +d, +h, +min, +s));
    if (isNaN(utcDate.getTime())) return null;

    const pad = (n) => String(n).padStart(2, "0");
    const year = utcDate.getFullYear();
    const month = pad(utcDate.getMonth() + 1);
    const day = pad(utcDate.getDate());
    const hours = pad(utcDate.getHours());
    const minutes = pad(utcDate.getMinutes());
    const seconds = pad(utcDate.getSeconds());

    return `${year}-${month}-${day} ${hours}:${minutes}:${seconds}`;
  }

  function convertScope(container = document) {
    const timestampRegex = /\b(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})\b/g;

    // 1. Explicit class/data elements
    container.querySelectorAll("[data-utc]:not([data-tz-done]), .utc-to-local:not([data-tz-done])").forEach((el) => {
      const raw = el.getAttribute("data-utc") || el.textContent.trim();
      const formatted = formatUtcTimestamp(raw);
      if (formatted) {
        el.textContent = formatted;
        el.dataset.tzDone = "true";
        el.title = `Local Time (${Intl.DateTimeFormat().resolvedOptions().timeZone || "Local"})\nServer UTC: ${raw}`;
      }
    });

    // 2. Targeted table cells and meta items
    const targetElements = container.querySelectorAll(
      "td:not([data-tz-done]), .feed-meta:not([data-tz-done]), .stat-sub:not([data-tz-done]), time:not([data-tz-done])"
    );

    targetElements.forEach((el) => {
      if (el.children.length === 0) {
        const text = el.textContent;
        if (text && timestampRegex.test(text)) {
          const newText = text.replace(timestampRegex, (match) => {
            return formatUtcTimestamp(match) || match;
          });
          if (newText !== text) {
            el.textContent = newText;
            el.dataset.tzDone = "true";
          }
        }
      }
    });
  }

  // Initial pass
  convertScope(document);

  // Modern MutationObserver handles AJAX/live tables efficiently with zero polling overhead
  try {
    const observer = new MutationObserver((mutations) => {
      for (const mutation of mutations) {
        for (const node of mutation.addedNodes) {
          if (node.nodeType === 1) {
            convertScope(node);
          }
        }
      }
    });
    observer.observe(document.body, { childList: true, subtree: true });
  } catch (e) {
    // Gentle fallback for older browsers
    setInterval(() => convertScope(document), 10000);
  }
}

