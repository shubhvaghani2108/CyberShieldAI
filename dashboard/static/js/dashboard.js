/* =========================================================
   CyberShieldAI — Dashboard interactivity
   Sidebar toggle, live clock, particles, scan modal, charts
   ========================================================= */

/* ---------------- Theme state & switcher ---------------- */
function getSystemTheme() {
  return window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

function getStoredTheme() {
  let stored = localStorage.getItem("csa-theme");
  if (!stored) {
    const match = document.cookie.match(new RegExp("(?:^|; )csa_theme=([^;]*)"));
    if (match) stored = decodeURIComponent(match[1]);
  }
  return stored || getSystemTheme();
}

function syncThemeUI(theme) {
  const isLight = theme === "light";
  document.querySelectorAll("[data-theme-toggle]").forEach((toggle) => {
    toggle.setAttribute("aria-pressed", isLight ? "true" : "false");
    const label = toggle.querySelector(".theme-toggle-label");
    if (label) label.textContent = isLight ? "Light" : "Dark";

    const sunIcon = toggle.querySelector(".theme-icon-sun");
    const moonIcon = toggle.querySelector(".theme-icon-moon");
    if (sunIcon && moonIcon) {
      sunIcon.style.display = isLight ? "inline-block" : "none";
      moonIcon.style.display = isLight ? "none" : "inline-block";
    }
  });
}

function applyTheme(theme) {
  const root = document.documentElement;
  root.setAttribute("data-theme", theme);
  syncThemeUI(theme);
  try {
    if (typeof updateChartsTheme === "function") {
      updateChartsTheme();
    }
  } catch (_) {}
}

function toggleTheme() {
  const root = document.documentElement;
  const current = root.getAttribute("data-theme") === "light" ? "light" : "dark";
  const next = current === "light" ? "dark" : "light";
  localStorage.setItem("csa-theme", next);
  document.cookie = "csa_theme=" + next + "; path=/; max-age=31536000; SameSite=Lax";
  applyTheme(next);
}

function initTheme() {
  const theme = getStoredTheme();
  applyTheme(theme);

  if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: light)").addEventListener("change", (e) => {
      if (!localStorage.getItem("csa-theme")) {
        applyTheme(e.matches ? "light" : "dark");
      }
    });
  }
}

// Global window helpers so external or inline buttons can invoke them safely
window.csaToggleTheme = toggleTheme;
window.csaApplyTheme = applyTheme;

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

/* ---------------- new scan modal programmatic helper ---------------- */
window.openScanModalWithTab = function (tabName) {
  const overlay = document.getElementById("newScanModal");
  if (!overlay) return;
  overlay.classList.add("open");
  const targetTab = document.querySelector(`[data-scan-tab="${tabName}"]`);
  if (targetTab) {
    targetTab.click();
  }
};

/* ---------------- Global Delegated Event Listeners (Always active, never unbound) ---------------- */
document.addEventListener("click", function (e) {
  // 1. Sidebar toggle button (Mobile & Tablet)
  const sidebarToggle = e.target.closest(".sidebar-toggle");
  if (sidebarToggle) {
    e.preventDefault();
    e.stopPropagation();
    const sidebar = document.querySelector(".sidebar") || document.getElementById("sidebar");
    const backdrop = document.getElementById("sidebarBackdrop");
    if (sidebar) {
      const willOpen = !sidebar.classList.contains("open");
      sidebar.classList.toggle("open", willOpen);
      if (backdrop) backdrop.classList.toggle("open", willOpen);
      sidebarToggle.setAttribute("aria-expanded", willOpen ? "true" : "false");
    }
    return;
  }

  // 2. Close Sidebar (Close button or Backdrop)
  const closeSidebarBtn = e.target.closest("[data-close-sidebar], #sidebarBackdrop");
  if (closeSidebarBtn) {
    e.preventDefault();
    const sidebar = document.querySelector(".sidebar") || document.getElementById("sidebar");
    const backdrop = document.getElementById("sidebarBackdrop");
    if (sidebar) sidebar.classList.remove("open");
    if (backdrop) backdrop.classList.remove("open");
    const toggle = document.querySelector(".sidebar-toggle");
    if (toggle) toggle.setAttribute("aria-expanded", "false");
    return;
  }

  // 3. Close Sidebar when clicking a navigation link
  const navLink = e.target.closest(".sidebar-nav a");
  if (navLink) {
    const sidebar = document.querySelector(".sidebar") || document.getElementById("sidebar");
    const backdrop = document.getElementById("sidebarBackdrop");
    if (sidebar && sidebar.classList.contains("open")) {
      sidebar.classList.remove("open");
      if (backdrop) backdrop.classList.remove("open");
      const toggle = document.querySelector(".sidebar-toggle");
      if (toggle) toggle.setAttribute("aria-expanded", "false");
    }
  }

  // 4. Open New Scan Modal
  const openScanBtn = e.target.closest("[data-open-scan-modal]");
  if (openScanBtn) {
    e.preventDefault();
    e.stopPropagation();
    const modal = document.getElementById("newScanModal");
    if (modal) {
      modal.classList.add("open");
      const activeForm = modal.querySelector('.scan-form:not([style*="display: none"])') || modal.querySelector(".scan-form");
      const input = activeForm ? activeForm.querySelector("input[type=text]") : null;
      if (input) setTimeout(() => input.focus(), 60);
    }
    return;
  }

  // 5. Close New Scan Modal (Cancel button or close icon)
  const closeScanBtn = e.target.closest("[data-close-scan-modal]");
  if (closeScanBtn) {
    e.preventDefault();
    e.stopPropagation();
    const modal = document.getElementById("newScanModal");
    if (modal) modal.classList.remove("open");
    return;
  }

  // 6. Click on Modal backdrop to dismiss
  if (e.target && e.target.id === "newScanModal") {
    e.target.classList.remove("open");
    return;
  }

  // 7. Theme Toggle Switch
  const themeToggle = e.target.closest("[data-theme-toggle]");
  if (themeToggle) {
    e.preventDefault();
    e.stopPropagation();
    toggleTheme();
    return;
  }

  // 8. Scan Modal Tabs (IP Scan vs URL Scan)
  const scanTab = e.target.closest("[data-scan-tab]");
  if (scanTab) {
    e.preventDefault();
    const target = scanTab.getAttribute("data-scan-tab");
    document.querySelectorAll("[data-scan-tab]").forEach((tab) => {
      const active = tab === scanTab;
      tab.classList.toggle("active", active);
      tab.setAttribute("aria-selected", active ? "true" : "false");
    });
    document.querySelectorAll("[data-scan-form]").forEach((form) => {
      form.style.display = form.getAttribute("data-scan-form") === target ? "" : "none";
    });
    const sub = document.getElementById("scanModalSub");
    if (sub) {
      if (target === "url") {
        sub.textContent = "Scan a website URL for web threats, SSL/TLS certificates, DNS records, and vulnerabilities.";
      } else {
        sub.textContent = "Scan an IP address for open ports, running services, and network vulnerabilities.";
      }
    }
    const targetForm = document.querySelector(`[data-scan-form="${target}"]`);
    const input = targetForm ? targetForm.querySelector("input[type=text]") : null;
    if (input) setTimeout(() => input.focus(), 50);
    return;
  }
});

// Global Escape Key to close modal or sidebar
document.addEventListener("keydown", function (e) {
  if (e.key === "Escape") {
    const modal = document.getElementById("newScanModal");
    if (modal && modal.classList.contains("open")) {
      modal.classList.remove("open");
    }
    const sidebar = document.querySelector(".sidebar") || document.getElementById("sidebar");
    const backdrop = document.getElementById("sidebarBackdrop");
    if (sidebar && sidebar.classList.contains("open")) {
      sidebar.classList.remove("open");
      if (backdrop) backdrop.classList.remove("open");
      const toggle = document.querySelector(".sidebar-toggle");
      if (toggle) toggle.setAttribute("aria-expanded", "false");
    }
  }
});

// Submit button single-click protection
document.addEventListener("submit", function (e) {
  const form = e.target.closest(".scan-form");
  if (form) {
    const submitBtn = form.querySelector('button[type="submit"]');
    if (submitBtn && !submitBtn.disabled) {
      setTimeout(() => {
        submitBtn.disabled = true;
        submitBtn.textContent = "Launching scan...";
      }, 0);
    }
  }
});

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
  const root = document.documentElement;
  const isLight = root.getAttribute("data-theme") === "light";
  return {
    isLight,
    textColor: isLight ? "#475569" : "#9aa4b5",
    gridColor: isLight ? "rgba(15,23,42,0.06)" : "rgba(255,255,255,0.06)",
    doughnutBorder: isLight ? "#ffffff" : "#12151c",
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

  // Cleanup prior chart instances
  while (activeChartInstances.length > 0) {
    const c = activeChartInstances.pop();
    try {
      c.destroy();
    } catch (_) {}
  }

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
    const total = (sev.critical || 0) + (sev.high || 0) + (sev.medium || 0) + (sev.low || 0);

    // Update DOM counts if elements exist
    const totalEl = document.getElementById("donutTotalCount");
    if (totalEl) totalEl.textContent = total;
    const cEl = document.getElementById("sevCountCrit");
    if (cEl) cEl.textContent = sev.critical || 0;
    const hEl = document.getElementById("sevCountHigh");
    if (hEl) hEl.textContent = sev.high || 0;
    const mEl = document.getElementById("sevCountMed");
    if (mEl) mEl.textContent = sev.medium || 0;
    const lEl = document.getElementById("sevCountLow");
    if (lEl) lEl.textContent = sev.low || 0;

    const chartConfig = total > 0 ? {
      labels: ["Critical", "High", "Medium", "Low"],
      datasets: [
        {
          data: [sev.critical || 0, sev.high || 0, sev.medium || 0, sev.low || 0],
          backgroundColor: ["#f43f5e", "#fb923c", "#eab308", "#22c55e"],
          borderColor: colors.doughnutBorder,
          borderWidth: 2,
          hoverOffset: 4,
        },
      ],
    } : {
      labels: ["None"],
      datasets: [
        {
          data: [1],
          backgroundColor: [colors.isLight ? "rgba(15,23,42,0.12)" : "rgba(255,255,255,0.08)"],
          borderColor: "transparent",
          borderWidth: 0,
        },
      ],
    };

    const chart = new Chart(sevCanvas, {
      type: "doughnut",
      data: chartConfig,
      options: {
        maintainAspectRatio: false,
        responsive: true,
        cutout: "74%",
        plugins: {
          legend: { display: false },
          tooltip: {
            enabled: total > 0,
            callbacks: {
              label: (ctx) => ` ${ctx.label}: ${ctx.parsed}`,
            },
          },
        },
      },
    });
    activeChartInstances.push(chart);
  }

  /* -------- Port / service distribution (bar) -------- */
  const portCanvas = document.getElementById("portChart");
  if (portCanvas) {
    const ports = data.port_distribution || [];
    const hasData = ports.length > 0;
    const chart = new Chart(portCanvas, {
      type: "bar",
      data: {
        labels: hasData ? ports.map((p) => p.label) : ["No open ports"],
        datasets: [
          {
            label: "Open ports",
            data: hasData ? ports.map((p) => p.count) : [0],
            backgroundColor: "#22d3ee",
            hoverBackgroundColor: "#38bdf8",
            borderRadius: 5,
            maxBarThickness: 32,
          },
        ],
      },
      options: {
        maintainAspectRatio: false,
        responsive: true,
        layout: {
          padding: { top: 10, bottom: 6, left: 4, right: 10 },
        },
        plugins: { legend: { display: false } },
        scales: {
          x: {
            grid: { display: false },
            ticks: { font: { size: 10 }, padding: 4 },
          },
          y: {
            beginAtZero: true,
            suggestedMax: hasData ? undefined : 2,
            grace: "8%",
            ticks: { precision: 0, stepSize: 1, font: { size: 10 } },
            grid: { color: colors.gridColor },
          },
        },
      },
    });
    activeChartInstances.push(chart);
  }

  /* -------- Risk trend across recent scans (line) -------- */
  const riskCanvas = document.getElementById("riskTrendChart");
  if (riskCanvas) {
    const trend = data.risk_trend || [];
    const hasData = trend.length > 0;
    const chart = new Chart(riskCanvas, {
      type: "line",
      data: {
        labels: hasData ? trend.map((t) => t.label) : ["Recent Target"],
        datasets: [
          {
            label: "Risk Score",
            data: hasData ? trend.map((t) => t.score) : [0],
            borderColor: "#c084fc",
            backgroundColor: "rgba(192,132,252,0.12)",
            fill: true,
            tension: 0.35,
            pointRadius: 4,
            pointHoverRadius: 6.5,
            pointHitRadius: 10,
            pointBackgroundColor: "#c084fc",
            pointBorderColor: "#ffffff",
            pointBorderWidth: 1.5,
          },
        ],
      },
      options: {
        maintainAspectRatio: false,
        responsive: true,
        layout: {
          padding: { top: 12, bottom: 6, left: 4, right: 12 },
        },
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
          x: {
            grid: { display: false },
            ticks: {
              maxRotation: 30,
              minRotation: 0,
              font: { size: 9.5 },
              autoSkip: true,
              maxTicksLimit: 6,
              padding: 4,
            },
          },
          y: {
            min: 0,
            suggestedMax: 105,
            grace: "6%",
            grid: { color: colors.gridColor },
            ticks: {
              stepSize: 20,
              font: { size: 9.5 },
              callback: function (value) {
                return value;
              },
            },
          },
        },
      },
    });
    activeChartInstances.push(chart);
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

/* ---------------- result tabs navigation ---------------- */
function initResultTabNavigation() {
  const tabsWrapper = document.querySelector(".result-section-tabs");
  const accordions = document.querySelectorAll(".section-accordion");
  const tabButtons = document.querySelectorAll(".result-tab-btn[data-tab]");
  const tabPanels = document.querySelectorAll(".result-view-panel");

  if (!tabsWrapper && !accordions.length) return;

  function activateTab(tabId, pushHash = true) {
    if (!tabId) tabId = "overview";
    // Strip # or tab- prefix if passed
    const cleanId = tabId.replace(/^#/, "").replace(/^tab-/, "");
    
    // Check for section accordion first (True Tab View: ONLY the selected section is visible)
    const targetSec = document.getElementById("sec-" + cleanId);
    let targetBtn = document.querySelector(`.result-tab-btn[data-tab="${cleanId}"]`);

    if (targetSec) {
      // 1. Hide ALL other sections completely (display: none), and show ONLY the selected section
      accordions.forEach((sec) => {
        if (sec === targetSec) {
          sec.style.display = "block";
          sec.open = true;
        } else if (cleanId === "ai" && sec.id === "sec-ai-recommendations") {
          // Special case: show both AI sections together
          sec.style.display = "block";
          sec.open = true;
        } else {
          sec.style.display = "none";
        }
      });

      // 2. Highlight the active tab button & horizontally scroll in tab bar
      tabButtons.forEach((b) => b.classList.remove("active"));
      if (targetBtn) {
        targetBtn.classList.add("active");
        targetBtn.scrollIntoView({ behavior: "smooth", inline: "nearest", block: "nearest" });
      }

      // 3. Update URL hash without page scrolling
      if (pushHash) {
        if (cleanId === "overview") {
          if (window.location.hash) {
            history.replaceState(null, null, window.location.pathname + window.location.search);
          }
        } else {
          history.replaceState(null, null, "#tab-" + cleanId);
        }
      }

      const toggleBtn = document.getElementById("toggleAllBtn");
      if (toggleBtn) {
        toggleBtn.textContent = "👁 View All Sections";
      }

      return;
    }

    let targetPanel = document.getElementById("panel-" + cleanId);
    if (!targetBtn) {
      targetBtn = document.querySelector(`.result-tab-btn[data-tab="${cleanId}"]`);
    }

    // Fallback to overview if not found
    if (!targetPanel) {
      targetPanel = document.getElementById("panel-overview");
      targetBtn = document.querySelector(`.result-tab-btn[data-tab="overview"]`);
    }

    if (!targetPanel) return;

    // Deactivate all panels & buttons
    tabPanels.forEach((p) => p.classList.remove("active"));
    tabButtons.forEach((b) => b.classList.remove("active"));

    // Activate target panel
    targetPanel.classList.add("active");
    if (targetBtn) {
      targetBtn.classList.add("active");
      targetBtn.scrollIntoView({ behavior: "smooth", inline: "nearest", block: "nearest" });
    }

    if (pushHash) {
      if (cleanId === "overview") {
        if (window.location.hash) {
          history.replaceState(null, null, window.location.pathname + window.location.search);
        }
      } else {
        history.replaceState(null, null, "#tab-" + cleanId);
      }
    }
  }

  // Expose globally
  window.activateResultTab = activateTab;

  // Bind click handlers to tab buttons (Switches section in place without vertical page scroll)
  tabButtons.forEach((btn) => {
    btn.addEventListener("click", (e) => {
      e.preventDefault();
      const tabId = btn.getAttribute("data-tab");
      activateTab(tabId, true);
    });
  });

  // Bind click handlers to all [data-switch-tab] elements anywhere on page (e.g. metric pills)
  document.addEventListener("click", (e) => {
    const trigger = e.target.closest("[data-switch-tab]");
    if (trigger) {
      e.preventDefault();
      const tabId = trigger.getAttribute("data-switch-tab");
      activateTab(tabId, true);
    }
  });

  // Check URL hash on page load
  const hash = window.location.hash;
  if (hash) {
    activateTab(hash, false);
  } else {
    activateTab("overview", false);
  }

  // Handle browser back/forward buttons
  window.addEventListener("hashchange", () => {
    const newHash = window.location.hash;
    activateTab(newHash || "overview", false);
  });
}

// Global helper to toggle all section accordions at once (View All Sections vs Single Tab)
window.toggleAllAccordions = function() {
  const accordions = document.querySelectorAll(".section-accordion");
  if (!accordions.length) return;
  const btn = document.getElementById("toggleAllBtn");
  const anyHidden = Array.from(accordions).some(a => a.style.display === "none");

  if (anyHidden) {
    // Show all sections
    accordions.forEach(a => {
      a.style.display = "block";
      a.open = true;
    });
    if (btn) btn.textContent = "📑 Single Section View";
    const tabButtons = document.querySelectorAll(".result-tab-btn[data-tab]");
    tabButtons.forEach(b => b.classList.remove("active"));
  } else {
    // Return to active tab or overview
    const activeBtn = document.querySelector(".result-tab-btn.active") || document.querySelector('.result-tab-btn[data-tab="overview"]');
    const tabId = activeBtn ? activeBtn.getAttribute("data-tab") : "overview";
    if (window.activateResultTab) {
      window.activateResultTab(tabId, true);
    }
    if (btn) btn.textContent = "👁 View All Sections";
  }
};

/* ---------------- Fast Navigation & Visual Progress ---------------- */
function initNavProgressBar() {
  const progressBar = document.getElementById("csa-nav-progress");

  function startProgress() {
    if (!progressBar) return;
    progressBar.classList.remove("done");
    progressBar.classList.add("animating");
    progressBar.style.width = "40%";
    setTimeout(() => {
      if (progressBar && progressBar.classList.contains("animating")) {
        progressBar.style.width = "78%";
      }
    }, 120);
  }

  // Animate progress bar on navigation click
  document.addEventListener("click", (e) => {
    if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.defaultPrevented) return;
    const anchor = e.target.closest("a");
    if (!anchor || !anchor.href) return;

    try {
      const url = new URL(anchor.href, window.location.origin);
      if (
        url.origin === window.location.origin &&
        !url.pathname.startsWith("/download") &&
        !anchor.hasAttribute("download") &&
        !anchor.target &&
        !anchor.hasAttribute("data-open-scan-modal") &&
        !anchor.hasAttribute("data-close-scan-modal")
      ) {
        startProgress();
      }
    } catch (_) {}
  });

  window.addEventListener("pageshow", () => {
    if (progressBar) {
      progressBar.classList.remove("animating");
      progressBar.classList.add("done");
      setTimeout(() => {
        if (progressBar) {
          progressBar.classList.remove("done");
          progressBar.style.width = "0%";
        }
      }, 300);
    }
  });
}

/* ---------------- Resilient Boot Sequence ---------------- */
function bootDashboard() {
  try { initTheme(); } catch (e) { console.error("Theme init error", e); }
  try { initClock(); } catch (e) { console.error("Clock init error", e); }
  try { initCharts(); } catch (e) { console.error("Charts init error", e); }
  try { initUtcToLocalTimestamps(); } catch (e) { console.error("Timestamps init error", e); }
  try { initResultTabNavigation(); } catch (e) { console.error("Tabs init error", e); }
  try { initNavProgressBar(); } catch (e) { console.error("Nav progress bar init error", e); }
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", bootDashboard);
} else {
  bootDashboard();
}



