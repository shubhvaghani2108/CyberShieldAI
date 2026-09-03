from database.db_engine import get_db_connection
import os
from datetime import datetime

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_FILE = os.path.join(BASE_DIR, "cybershield.db")


def save_url_intelligence(data, scan_id=None):
    whois_info = data.get("whois") or {}
    geoip_info = data.get("geoip") or {}
    waf_info = data.get("waf") or {}

    registrar = whois_info.get("registrar", "N/A")
    creation_date = whois_info.get("creation_date", "N/A")
    expiration_date = whois_info.get("expiration_date", "N/A")
    updated_date = whois_info.get("updated_date", "N/A")

    if whois_info.get("is_ip") or registrar in (None, "", "Unknown"):
        if whois_info.get("is_ip"):
            registrar = "N/A"
            creation_date = "N/A"
            expiration_date = "N/A"
            updated_date = "N/A"

    target_ip = data.get("ip", "Unknown")
    is_geoip_assessed = geoip_info.get("is_assessed")
    if target_ip in ("Unknown", "unknown", None, "") or is_geoip_assessed is False:
        country = "Unknown"
        region = "Unknown"
        city = "Unknown"
        isp = "Unknown"
        asn = "Unknown"
    else:
        country = geoip_info.get("country", "Unknown")
        region = geoip_info.get("region", "Unknown")
        city = geoip_info.get("city", "Unknown")
        isp = geoip_info.get("isp", "Unknown")
        asn = geoip_info.get("asn", "Unknown")

    import json
    dns_info = data.get("dns") or {}
    dns_json = json.dumps(dns_info)

    conn = get_db_connection()
    try:
        cur = conn.cursor()

        has_dns_col = False
        try:
            cur.execute("PRAGMA table_info(url_intelligence)")
            cols = [r["name"] if hasattr(r, "keys") else r[1] for r in cur.fetchall()]
            if "dns_records" in cols:
                has_dns_col = True
            else:
                try:
                    cur.execute("ALTER TABLE url_intelligence ADD COLUMN dns_records TEXT")
                    conn.commit()
                    has_dns_col = True
                except Exception:
                    pass
        except Exception:
            pass

        if has_dns_col:
            cur.execute("""
            INSERT INTO url_intelligence(
                scan_id,
                ip,
                url,
                registrar,
                creation_date,
                expiration_date,
                updated_date,
                country,
                region,
                city,
                isp,
                asn,
                waf,
                dns_records,
                scan_time
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                scan_id or data.get("scan_id"),
                target_ip,
                data.get("url", ""),
                registrar,
                creation_date,
                expiration_date,
                updated_date,
                country,
                region,
                city,
                isp,
                asn,
                waf_info.get("provider", "None"),
                dns_json,
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))
        else:
            cur.execute("""
            INSERT INTO url_intelligence(
                scan_id,
                ip,
                url,
                registrar,
                creation_date,
                expiration_date,
                updated_date,
                country,
                region,
                city,
                isp,
                asn,
                waf,
                scan_time
            )
            VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """, (
                scan_id or data.get("scan_id"),
                target_ip,
                data.get("url", ""),
                registrar,
                creation_date,
                expiration_date,
                updated_date,
                country,
                region,
                city,
                isp,
                asn,
                waf_info.get("provider", "None"),
                datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            ))

        conn.commit()
        print("[OK] URL Intelligence Saved")
    except Exception as e:
        print(f"[URL INTEL] Error saving intelligence data: {e}")
    finally:
        conn.close()