import os
import sys

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from database.db_helpers import get_db_connection


# ==========================================================
# 1. Add Monitored Target
# ==========================================================
def add_monitored_target(target, frequency=24):
    """
    Inserts a target into the monitored_targets table.
    Returns True on success, False on failure.
    """
    if not target:
        return False

    clean_target = str(target).strip()
    if not clean_target:
        return False

    try:
        freq = int(frequency) if frequency is not None else 24
    except (ValueError, TypeError):
        freq = 24

    conn = None
    try:
        conn = get_db_connection()
        conn.execute(
            """
            INSERT INTO monitored_targets (target, scan_frequency, enabled)
            VALUES (?, ?, 1)
            """,
            (clean_target, freq),
        )
        conn.commit()
        return True
    except Exception as e:
        print(f"[ERROR] Failed to add monitored target '{clean_target}': {e}")
        return False
    finally:
        if conn:
            conn.close()


def is_target_exists(target):
    """
    Checks if a target already exists in the monitored_targets table.
    Performs case-insensitive and trailing-slash normalized comparison.
    """
    if not target:
        return False

    clean_target = str(target).strip().rstrip("/").lower()
    targets = get_monitored_targets()
    for t in targets:
        existing = str(t.get("target", "")).strip().rstrip("/").lower()
        if existing == clean_target:
            return True
    return False



# ==========================================================
# 2. Get All Monitored Targets
# ==========================================================
def get_monitored_targets():
    """
    Retrieves all monitored targets from monitored_targets table.
    Returns a list of dictionaries.
    """
    conn = None
    try:
        conn = get_db_connection()
        rows = conn.execute(
            """
            SELECT id, target, scan_frequency, enabled, created_at
            FROM monitored_targets
            ORDER BY id DESC
            """
        ).fetchall()
        return [dict(row) for row in rows]
    except Exception as e:
        print(f"[ERROR] Failed to fetch monitored targets: {e}")
        return []
    finally:
        if conn:
            conn.close()


# ==========================================================
# 3. Get Single Monitored Target
# ==========================================================
def get_monitored_target(target_id):
    """
    Retrieves a single monitored target by its ID.
    Returns a dictionary if found, otherwise None.
    """
    if target_id is None:
        return None

    conn = None
    try:
        conn = get_db_connection()
        row = conn.execute(
            """
            SELECT id, target, scan_frequency, enabled, created_at
            FROM monitored_targets
            WHERE id = ?
            """,
            (target_id,),
        ).fetchone()
        return dict(row) if row else None
    except Exception as e:
        print(f"[ERROR] Failed to fetch monitored target #{target_id}: {e}")
        return None
    finally:
        if conn:
            conn.close()


# ==========================================================
# 4. Delete Monitored Target
# ==========================================================
def delete_monitored_target(target_id):
    """
    Deletes a monitored target by target_id.
    Returns True on success, False on failure.
    """
    if target_id is None:
        return False

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.execute(
            """
            DELETE FROM monitored_targets
            WHERE id = ?
            """,
            (target_id,),
        )
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        print(f"[ERROR] Failed to delete monitored target #{target_id}: {e}")
        return False
    finally:
        if conn:
            conn.close()


# ==========================================================
# 5. Enable Monitoring
# ==========================================================
def enable_monitoring(target_id):
    """
    Sets enabled = 1 for a given target_id.
    Returns True on success, False on failure.
    """
    if target_id is None:
        return False

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.execute(
            """
            UPDATE monitored_targets
            SET enabled = 1
            WHERE id = ?
            """,
            (target_id,),
        )
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        print(f"[ERROR] Failed to enable monitoring for #{target_id}: {e}")
        return False
    finally:
        if conn:
            conn.close()


# ==========================================================
# 6. Disable Monitoring
# ==========================================================
def disable_monitoring(target_id):
    """
    Sets enabled = 0 for a given target_id.
    Returns True on success, False on failure.
    """
    if target_id is None:
        return False

    conn = None
    try:
        conn = get_db_connection()
        cur = conn.execute(
            """
            UPDATE monitored_targets
            SET enabled = 0
            WHERE id = ?
            """,
            (target_id,),
        )
        conn.commit()
        return cur.rowcount > 0
    except Exception as e:
        print(f"[ERROR] Failed to disable monitoring for #{target_id}: {e}")
        return False
    finally:
        if conn:
            conn.close()


# ==========================================================
# 7. Count Monitored Targets
# ==========================================================
def count_monitored_targets():
    """
    Returns the total count of monitored targets.
    """
    conn = None
    try:
        conn = get_db_connection()
        row = conn.execute(
            "SELECT COUNT(*) AS total FROM monitored_targets"
        ).fetchone()
        return row["total"] if row else 0
    except Exception as e:
        print(f"[ERROR] Failed to count monitored targets: {e}")
        return 0
    finally:
        if conn:
            conn.close()


# ==========================================================
# Monitoring Dashboard Analytics Helper
# ==========================================================
def get_monitoring_analytics():
    """
    Computes summary analytics for monitored assets:
    - Total Monitored Assets
    - Healthy Assets
    - Warning Assets
    - Critical Assets
    - Last Monitoring Run
    """
    targets = get_monitored_targets()
    total_assets = len(targets)
    healthy_count = 0
    warning_count = 0
    critical_count = 0
    last_run = None

    conn = None
    try:
        conn = get_db_connection()
        for t in targets:
            target_val = t["target"]
            like_target = f"%{target_val}%"

            row = conn.execute(
                """
                SELECT risk, score, scan_time FROM url_scan_results
                WHERE (ip = ? OR domain = ? OR url = ? OR url LIKE ?)
                ORDER BY id DESC LIMIT 1
                """,
                (target_val, target_val, target_val, like_target),
            ).fetchone()

            if not row:
                row = conn.execute(
                    """
                    SELECT risk_level AS risk, total_score AS score, scan_time FROM risk_summary
                    WHERE ip = ?
                    ORDER BY id DESC LIMIT 1
                    """,
                    (target_val,),
                ).fetchone()

            if row:
                risk_level = str(row["risk"] or "Low").strip().lower()
                score = row["score"] or 0
                scan_time = row["scan_time"]

                if scan_time and (not last_run or str(scan_time) > str(last_run)):
                    last_run = scan_time

                if risk_level in ["critical", "high"] or score >= 40:
                    critical_count += 1
                elif risk_level in ["medium", "warn", "warning"] or (25 <= score < 40):
                    warning_count += 1
                else:
                    healthy_count += 1
            else:
                healthy_count += 1

        if not last_run:
            latest_row = conn.execute(
                "SELECT scan_time FROM url_scan_results ORDER BY id DESC LIMIT 1"
            ).fetchone()
            if not latest_row:
                latest_row = conn.execute(
                    "SELECT scan_time FROM scan_history ORDER BY id DESC LIMIT 1"
                ).fetchone()
            if latest_row and latest_row["scan_time"]:
                last_run = latest_row["scan_time"]

        return {
            "total_monitored_assets": total_assets,
            "healthy_assets": healthy_count,
            "warning_assets": warning_count,
            "critical_assets": critical_count,
            "last_monitoring_run": last_run or "No Runs Yet",
        }
    except Exception as e:
        print(f"[ERROR] Failed to calculate monitoring analytics: {e}")
        return {
            "total_monitored_assets": total_assets,
            "healthy_assets": total_assets,
            "warning_assets": 0,
            "critical_assets": 0,
            "last_monitoring_run": "No Runs Yet",
        }
    finally:
        if conn:
            conn.close()
