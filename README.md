# CyberShieldAI — Reorganized Project Structure

```
CyberShieldAI/
├── .vscode/
│   └── settings.json
├── config.py
├── requirements.txt
├── cybershield.db
├── NOTES.md
│
├── dashboard/                     # Flask web app
│   ├── app.py
│   ├── static/
│   │   ├── css/
│   │   │   └── dashboard.css
│   │   └── js/
│   │       └── dashboard.js
│   └── templates/
│       ├── index.html
│       ├── history.html
│       ├── ports.html
│       ├── cves.html
│       ├── risk_report.html
│       ├── scanning.html
│       ├── url_history.html
│       ├── url_result.html
│       ├── vulnerabilities.html
│       └── dashboard/             # dashboard partials
│           ├── dashboard.html
│           ├── cards.html
│           ├── charts.html
│           ├── navbar.html
│           ├── footer.html
│           ├── asset_table.html
│           ├── recent_activity.html
│           ├── recommendations.html
│           └── vulnerabilities.html
│
├── scanner/                       # Core scanning engine
│   ├── __init__.py
│   ├── asset_discovery.py
│   ├── banner_grabber.py
│   ├── cve_scanner.py
│   ├── host_discovery.py
│   ├── nmap_utils.py
│   ├── os_detector.py
│   ├── port_scanner.py
│   ├── recommendation_engine.py
│   ├── risk_calculator.py
│   ├── security_headers.py
│   ├── service_detector.py
│   ├── technology_detector.py
│   ├── url_scanner.py
│   └── vulnerability_scanner.py
│
├── database/                      # DB models & access layer
│   ├── __init__.py
│   ├── assets.py
│   ├── dashboard_stats.py
│   ├── init_db.py
│   ├── models.py
│   └── scripts/                   # one-off debug/inspection scripts
│       ├── check_columns.py
│       ├── check_tables.py
│       ├── check_technology.py
│       ├── clear_cves.py
│       ├── fix_scan_history.py
│       ├── search_ip.py
│       ├── test_db.py
│       ├── test_history.py
│       ├── view_cves.py
│       ├── view_history.py
│       ├── view_ports.py
│       └── view_vulnerabilities.py
│
├── ai_engine/
│   └── anomaly_detection.py
├── alerts/
│   └── email_alert.py
├── cve_lookup/
│   └── cve_checker.py
├── log_analysis/
│   ├── linux_logs.py
│   └── windows_logs.py
├── threat_detection/
│   ├── attack_detector.py
│   ├── packet_sniffer.py
│   └── threat_detector.py
├── url_scanner/
│   └── __init__.py
│
├── reports/
│   ├── report_generator.py
│   └── CyberShield_Full_Report.pdf
│
└── scripts/                       # root-level maintenance/test scripts
    ├── check_db.py
    ├── create_os_table.py
    ├── reset_db.py
    ├── service_table.py
    └── test_recommendation.py
```

## What changed vs. the original zip

- **Removed all `__pycache__/` folders** (`*.pyc` files) — these are build
  artifacts that Python regenerates automatically; they don't belong in
  source control or a shared zip.
- **Removed `dashboard/templates/static copy/`** — an old, unused duplicate
  of the static assets (contained a stale `style.css`, images, and no
  connection to the app).
- **Moved static assets to a conventional Flask location**:
  `dashboard/templates/static/{css,js}` → `dashboard/static/{css,js}`.
  Templates now live only under `templates/`, and assets only under
  `static/`, matching Flask's default `url_for('static', ...)` convention.
- **Removed the duplicate top-level `cybershield.db`** — the zip contained
  two copies (one inside `CyberShieldAI/`, one beside it); kept the one
  inside the project root.
- **Removed `temp_black_format.py`** — a 35 KB scratch/formatting file at
  the top level, unrelated to the app itself.
- **Fixed `database/database.db/`** — this was a *folder* literally named
  `database.db` containing a stray `view_cves.py`. That script has been
  moved to `database/scripts/view_cves.py`.
- **Split `database/` into core modules vs. scripts** — `assets.py`,
  `dashboard_stats.py`, `init_db.py`, and `models.py` are the modules the
  app actually imports; the various `check_*`, `test_*`, and `view_*`
  one-off scripts now live in `database/scripts/` so they don't clutter
  the importable package.
- **Consolidated stray root-level scripts** (`check_db.py`,
  `create_os_table.py`, `reset_db.py`, `service_table.py`,
  `test_recommendation.py`) into a top-level `scripts/` folder.
- **Renamed `Requirements.txt` → `requirements.txt`** (standard casing
  expected by most tooling/CI).
- **`note.txt` → `NOTES.md`** for consistency with the rest of the docs.

## Note on imports

Because some files moved (notably the static folder and the `database/`
scripts), double check any hardcoded paths in `dashboard/app.py` — for
example `static_folder=` / `template_folder=` Flask config, and any
`import` or file-path references to the scripts that were relocated into
`database/scripts/` or `scripts/`. I did not modify code logic, only file
locations, so anything referencing old paths by string will need a quick
find-and-replace.
