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

