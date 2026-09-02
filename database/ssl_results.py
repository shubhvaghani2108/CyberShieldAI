"""
database/ssl_results.py

Persists the dict returned by scanner.ssl_scanner.analyze_ssl() into a
`ssl_results` table. Opens its own sqlite3 connection (same DB file
used everywhere else in the project) so it has no import dependency
on dashboard/app.py — avoids circular imports.
"""

import os
import sqlite3
import json
from datetime import datetime

from database.db_engine import get_db_connection

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "cybershield.db")


def _get_conn():
    return get_db_connection()


def init_ssl_table():
    conn = _get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS ssl_results (
            id                 INTEGER PRIMARY KEY AUTOINCREMENT,
            host               TEXT,
            port               INTEGER,
            has_ssl            INTEGER,
            tls_version        TEXT,
            cipher_suite       TEXT,
            key_type           TEXT,
            key_size           TEXT,
            fingerprint_sha256 TEXT,
            cert_chain         TEXT,
            san_names          TEXT,
            issuer             TEXT,
            subject            TEXT,
            valid_from         TEXT,
            valid_to           TEXT,
            days_remaining     INTEGER,
            self_signed        INTEGER,
            expired            INTEGER,
            warnings           TEXT,
            scan_time          TEXT
        )
        """
    )
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(ssl_results)")
    cols = [r[1] for r in cursor.fetchall()]
    new_cols = [
        ("cipher_suite", "TEXT"),
        ("key_type", "TEXT"),
        ("key_size", "TEXT"),
        ("fingerprint_sha256", "TEXT"),
        ("cert_chain", "TEXT"),
        ("san_names", "TEXT"),
    ]
    for col_name, col_type in new_cols:
        if col_name not in cols:
            cursor.execute(f"ALTER TABLE ssl_results ADD COLUMN {col_name} {col_type}")
    conn.commit()
    conn.close()


init_ssl_table()


def save_ssl(ssl_data: dict, scan_id: str = None):
    """
    Save one SSL analysis result (the dict returned by analyze_ssl()).
    Silently ignores a None/empty input.
    """
    if not ssl_data:
        return

    conn = _get_conn()
    san_val = ssl_data.get("san_names")
    if isinstance(san_val, list):
        san_str = json.dumps(san_val)
    else:
        san_str = str(san_val or "")

    conn.execute(
        """
        INSERT INTO ssl_results
        (scan_id, host, port, has_ssl, tls_version, cipher_suite, key_type, key_size,
         fingerprint_sha256, cert_chain, san_names, issuer, subject,
         valid_from, valid_to, days_remaining, self_signed,
         expired, warnings, scan_time)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id or ssl_data.get("scan_id"),
            ssl_data.get("host"),
            ssl_data.get("port"),
            1 if ssl_data.get("has_ssl") else 0,
            ssl_data.get("tls_version"),
            ssl_data.get("cipher_suite"),
            ssl_data.get("key_type"),
            ssl_data.get("key_size"),
            ssl_data.get("fingerprint_sha256"),
            ssl_data.get("cert_chain"),
            san_str,
            ssl_data.get("issuer"),
            ssl_data.get("subject"),
            ssl_data.get("valid_from"),
            ssl_data.get("valid_to"),
            ssl_data.get("days_remaining"),
            1 if ssl_data.get("self_signed") else 0,
            1 if ssl_data.get("expired") else 0,
            " | ".join(ssl_data.get("warnings", [])) if ssl_data.get("warnings") else "",
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        ),
    )
    conn.commit()
    conn.close()


def get_latest_ssl(host: str, scan_id=None):
    conn = _get_conn()
    row = None
    if scan_id:
        row = conn.execute(
            """
            SELECT *
            FROM ssl_results
            WHERE scan_id = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (scan_id,),
        ).fetchone()

    if not row and host:
        row = conn.execute(
            """
            SELECT *
            FROM ssl_results
            WHERE host = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (host,),
        ).fetchone()
    conn.close()
    if row:
        res = dict(row)
        if res.get("san_names"):
            try:
                res["parsed_san_names"] = json.loads(res["san_names"])
            except Exception:
                res["parsed_san_names"] = [res["san_names"]]
        else:
            res["parsed_san_names"] = []

        if not res.get("chain_hierarchy"):
            iss = res.get("issuer") or ""
            sub = res.get("subject") or host
            root_name = "Trusted Public Root CA"
            if iss:
                iss_lower = iss.lower()
                if "google" in iss_lower or "gts" in iss_lower:
                    root_name = "GTS Root R1 (GlobalSign / Google Trust Services)"
                elif "let's encrypt" in iss_lower or "isrg" in iss_lower or "r3" in iss_lower:
                    root_name = "ISRG Root X1 (Let's Encrypt / TrustID)"
                elif "digicert" in iss_lower:
                    root_name = "DigiCert Global Root CA"
                elif "sectigo" in iss_lower or "comodo" in iss_lower:
                    root_name = "Sectigo RSA Root CA"
                elif "amazon" in iss_lower:
                    root_name = "Amazon Root CA 1"
                elif "cloudflare" in iss_lower:
                    root_name = "Cloudflare Inc ECC Root CA"
                else:
                    root_name = f"{iss.split(',')[0]} (Root CA)"
            res["chain_hierarchy"] = {
                "root": root_name,
                "intermediate": iss or "Public Authority CA",
                "leaf": sub
            }
        return res
    return None


def get_previous_ssl(host, current_id=None):
    conn = _get_conn()

    if current_id is not None:
        row = conn.execute(
            """
            SELECT *
            FROM ssl_results
            WHERE host = ?
              AND id < ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (host, current_id),
        ).fetchone()
    else:
        row = conn.execute(
            """
            SELECT *
            FROM ssl_results
            WHERE host = ?
            ORDER BY id DESC
            LIMIT 1 OFFSET 1
            """,
            (host,),
        ).fetchone()

    conn.close()

    return dict(row) if row else None
