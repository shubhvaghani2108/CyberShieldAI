import secrets
from datetime import datetime
from database.db_engine import get_db_connection


def init_agent_tables():
    """Initializes dedicated tables for local agent management without touching any existing tables."""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_tokens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                token TEXT UNIQUE,
                name TEXT,
                created_at TEXT,
                last_seen TEXT
            )
            """
        )
        cursor.execute("PRAGMA table_info(agent_tokens)")
        cols = [r["name"] if hasattr(r, "keys") else r[1] for r in cursor.fetchall()]
        if "user_id" not in cols:
            try:
                cursor.execute("ALTER TABLE agent_tokens ADD COLUMN user_id INTEGER")
            except Exception:
                pass
        if "token" not in cols:
            try:
                cursor.execute("ALTER TABLE agent_tokens ADD COLUMN token TEXT")
            except Exception:
                pass
        if "name" not in cols:
            try:
                cursor.execute("ALTER TABLE agent_tokens ADD COLUMN name TEXT")
            except Exception:
                pass
        if "created_at" not in cols:
            try:
                cursor.execute("ALTER TABLE agent_tokens ADD COLUMN created_at TEXT")
            except Exception:
                pass
        if "last_seen" not in cols:
            try:
                cursor.execute("ALTER TABLE agent_tokens ADD COLUMN last_seen TEXT")
            except Exception:
                pass

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS agent_jobs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT UNIQUE,
                scan_id TEXT,
                target TEXT,
                user_id INTEGER,
                status TEXT,
                created_at TEXT,
                completed_at TEXT
            )
            """
        )
        cursor.execute("PRAGMA table_info(agent_jobs)")
        j_cols = [r["name"] if hasattr(r, "keys") else r[1] for r in cursor.fetchall()]
        if "job_id" not in j_cols:
            try:
                cursor.execute("ALTER TABLE agent_jobs ADD COLUMN job_id TEXT")
            except Exception:
                pass
        if "scan_id" not in j_cols:
            try:
                cursor.execute("ALTER TABLE agent_jobs ADD COLUMN scan_id TEXT")
            except Exception:
                pass
        if "target" not in j_cols:
            try:
                cursor.execute("ALTER TABLE agent_jobs ADD COLUMN target TEXT")
            except Exception:
                pass
        if "user_id" not in j_cols:
            try:
                cursor.execute("ALTER TABLE agent_jobs ADD COLUMN user_id INTEGER")
            except Exception:
                pass
        if "status" not in j_cols:
            try:
                cursor.execute("ALTER TABLE agent_jobs ADD COLUMN status TEXT")
            except Exception:
                pass
        if "created_at" not in j_cols:
            try:
                cursor.execute("ALTER TABLE agent_jobs ADD COLUMN created_at TEXT")
            except Exception:
                pass
        if "completed_at" not in j_cols:
            try:
                cursor.execute("ALTER TABLE agent_jobs ADD COLUMN completed_at TEXT")
            except Exception:
                pass

        conn.commit()
    finally:
        conn.close()


def register_agent(user_id, name="Default Local Agent"):
    """Generates and registers a new secure API token for a user's local scanner agent."""
    token = f"csa_agent_{secrets.token_hex(24)}"
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO agent_tokens (user_id, token, name, created_at, last_seen)
            VALUES (?, ?, ?, ?, ?)
            """,
            (user_id, token, name, now, None),
        )
        conn.commit()
        return {
            "token": token,
            "name": name,
            "user_id": user_id,
            "created_at": now,
        }
    finally:
        conn.close()


def get_agent_by_token(token):
    """Retrieves an agent record by its authentication token."""
    if not token:
        return None
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, user_id, token, name, created_at, last_seen FROM agent_tokens WHERE token = ? LIMIT 1",
            (token,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)
    finally:
        conn.close()


def touch_agent(token):
    """Updates the last_seen heartbeat timestamp for an active agent."""
    if not token:
        return
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE agent_tokens SET last_seen = ? WHERE token = ?",
            (now, token),
        )
        conn.commit()
    finally:
        conn.close()


def list_agents_for_user(user_id):
    """Lists all registered agent tokens for a specific user."""
    if not user_id:
        return []
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT id, user_id, token, name, created_at, last_seen FROM agent_tokens WHERE user_id = ? ORDER BY id DESC",
            (user_id,),
        )
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def create_agent_job(job_id, scan_id, target, user_id):
    """Creates a pending scan job queued for execution by a user's local agent."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO agent_jobs (job_id, scan_id, target, user_id, status, created_at, completed_at)
            VALUES (?, ?, ?, ?, 'pending', ?, NULL)
            """,
            (job_id, scan_id, target, user_id, now),
        )
        conn.commit()
        return {
            "job_id": job_id,
            "scan_id": scan_id,
            "target": target,
            "user_id": user_id,
            "status": "pending",
            "created_at": now,
        }
    finally:
        conn.close()


def get_pending_jobs_for_user(user_id):
    """Retrieves all pending scan jobs for a user's local agents."""
    if not user_id:
        return []
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, job_id, scan_id, target, user_id, status, created_at
            FROM agent_jobs
            WHERE user_id = ? AND status = 'pending'
            ORDER BY id ASC
            """,
            (user_id,),
        )
        rows = cursor.fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_agent_job(job_id):
    """Retrieves a single agent job by job_id."""
    if not job_id:
        return None
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, job_id, scan_id, target, user_id, status, created_at, completed_at
            FROM agent_jobs
            WHERE job_id = ?
            LIMIT 1
            """,
            (job_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return dict(row)
    finally:
        conn.close()


def complete_agent_job(job_id):
    """Marks an agent job as completed."""
    if not job_id:
        return
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "UPDATE agent_jobs SET status = 'completed', completed_at = ? WHERE job_id = ?",
            (now, job_id),
        )
        conn.commit()
    finally:
        conn.close()


def save_agent_port_results(scan_id, target, open_ports):
    """
    Saves port scan results reported by a Local Scan Agent.
    Strictly additive: INSERTs into the existing ports and service_versions tables (same schema),
    and updates host_status and scan_history to 'Alive' for this scan_id only.
    """
    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        for p_info in open_ports:
            try:
                port_num = int(p_info.get("port", 0))
            except (ValueError, TypeError):
                continue
            state = p_info.get("state", "open")
            service = p_info.get("service", "unknown")
            banner = p_info.get("banner", "")
            product = p_info.get("product", "")
            version = p_info.get("version", "")
            extra_info = p_info.get("extra_info", "Local Scan Agent (LAN)")

            cursor.execute(
                """
                INSERT INTO ports (scan_id, ip, port, state, service, banner, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, target, port_num, state, service, banner, scan_time),
            )
            cursor.execute(
                """
                INSERT INTO service_versions (scan_id, ip, port, service, product, version, extra_info, scan_time)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (scan_id, target, port_num, service, product, version, extra_info, scan_time),
            )

        # Update host_status and scan_history to 'Alive' for this scan_id only
        cursor.execute(
            "UPDATE host_status SET status = 'Alive' WHERE scan_id = ? AND target_ip = ?",
            (scan_id, target),
        )
        cursor.execute(
            "UPDATE scan_history SET status = 'Alive' WHERE scan_id = ? AND target_ip = ?",
            (scan_id, target),
        )
        conn.commit()
    finally:
        conn.close()
