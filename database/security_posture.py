import os
from database.db_engine import get_db_connection

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "cybershield.db")


def _get_conn():
    return get_db_connection()


def init_security_posture_table():
    conn = _get_conn()
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS security_posture (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            scan_id TEXT,
            ip TEXT,
            url TEXT,
            security_score INTEGER,
            security_grade TEXT,
            threat_score INTEGER,
            risk_level TEXT,
            assessment_status TEXT DEFAULT 'ASSESSED',
            scan_time TEXT
        )
        """
    )
    # Migration: check columns
    cursor = conn.cursor()
    cursor.execute("PRAGMA table_info(security_posture)")
    cols = [r["name"] for r in cursor.fetchall()]
    if "assessment_status" not in cols:
        cursor.execute("ALTER TABLE security_posture ADD COLUMN assessment_status TEXT DEFAULT 'ASSESSED'")
    if "scan_id" not in cols:
        cursor.execute("ALTER TABLE security_posture ADD COLUMN scan_id TEXT")
    if "user_id" not in cols:
        cursor.execute("ALTER TABLE security_posture ADD COLUMN user_id INTEGER DEFAULT 1")
    conn.commit()
    conn.close()


init_security_posture_table()


def save_security_posture(
    ip: str,
    url: str,
    security_score,
    security_grade: str,
    threat_score: int = 0,
    risk_level: str = "Low",
    scan_time: str = None,
    scan_id: str = None,
    assessment_status: str = "ASSESSED",
    user_id: int = None,
):
    if not scan_time:
        scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    if security_score is None:
        assessment_status = "INCONCLUSIVE"

    conn = _get_conn()
    cursor = conn.cursor()

    existing = None
    if scan_id:
        existing = cursor.execute("SELECT id FROM security_posture WHERE scan_id = ?", (scan_id,)).fetchone()
    if not existing:
        existing = cursor.execute(
            "SELECT id FROM security_posture WHERE ip = ? AND url = ? AND scan_time = ?",
            (ip, url, scan_time)
        ).fetchone()

    score_val = int(security_score) if security_score is not None else None
    grade_val = str(security_grade or "N/A")
    t_score_val = int(threat_score or 0)
    risk_val = str(risk_level or "Low")

    if existing:
        posture_id = existing["id"]
        if user_id is not None:
            cursor.execute(
                """
                UPDATE security_posture
                SET security_score = ?, security_grade = ?, threat_score = ?, risk_level = ?, assessment_status = ?, scan_time = ?, user_id = ?
                WHERE id = ?
                """,
                (
                    score_val,
                    grade_val,
                    t_score_val,
                    risk_val,
                    assessment_status,
                    scan_time,
                    user_id,
                    posture_id
                )
            )
        else:
            cursor.execute(
                """
                UPDATE security_posture
                SET security_score = ?, security_grade = ?, threat_score = ?, risk_level = ?, assessment_status = ?, scan_time = ?
                WHERE id = ?
                """,
                (
                    score_val,
                    grade_val,
                    t_score_val,
                    risk_val,
                    assessment_status,
                    scan_time,
                    posture_id
                )
            )
    else:
        cursor.execute(
            """
            INSERT INTO security_posture
            (scan_id, user_id, ip, url, security_score, security_grade, threat_score, risk_level, assessment_status, scan_time)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                user_id,
                ip,
                url,
                score_val,
                grade_val,
                t_score_val,
                risk_val,
                assessment_status,
                scan_time
            )
        )
        posture_id = cursor.lastrowid

    conn.commit()
    conn.close()

    print(f"[POSTURE] Security posture saved: {score_val if score_val is not None else 'N/A'}/100 ({grade_val}) status={assessment_status} [scan_id={scan_id}]")
    return posture_id


def get_previous_security_posture(target: str, current_id: int = None):
    """
    Retrieves the previous security posture record for an IP or URL.
    """
    conn = _get_conn()
    like_target = f"%{target}%"

    if current_id is not None:
        row = conn.execute(
            """
            SELECT *
            FROM security_posture
            WHERE (ip = ? OR url = ? OR url LIKE ?)
              AND id < ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (target, target, like_target, current_id),
        ).fetchone()
    else:
        row = conn.execute(
            """
            SELECT *
            FROM security_posture
            WHERE ip = ? OR url = ? OR url LIKE ?
            ORDER BY id DESC
            LIMIT 1 OFFSET 1
            """,
            (target, target, like_target),
        ).fetchone()

    conn.close()
    return dict(row) if row else None


def get_latest_security_posture(target: str):
    """
    Retrieves the latest security posture record for an IP or URL.
    """
    conn = _get_conn()
    like_target = f"%{target}%"
    row = conn.execute(
        """
        SELECT *
        FROM security_posture
        WHERE ip = ? OR url = ? OR url LIKE ?
        ORDER BY id DESC
        LIMIT 1
        """,
        (target, target, like_target),
    ).fetchone()
    conn.close()
    return dict(row) if row else None
