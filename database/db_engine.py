import os
import re
import sys
from collections.abc import Mapping

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)


def get_database_url():
    """
    Resolves the PostgreSQL DATABASE_URL from environment variables or .env file.
    Does not log credentials.
    Supports Supabase Session Pooler strings by cleaning up unsupported psycopg2 parameters.
    """
    url = os.environ.get("DATABASE_URL")
    if not url:
        env_file = os.path.join(BASE_DIR, ".env")
        if os.path.exists(env_file):
            try:
                with open(env_file, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("DATABASE_URL="):
                            val = line.split("=", 1)[1].strip().strip('"').strip("'")
                            if val:
                                url = val
                                break
            except Exception:
                pass

    if url:
        url = url.strip()
        # Clean up Supabase pooler query parameters that psycopg2 rejects
        from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
        try:
            parsed = urlparse(url)
            qs = parse_qs(parsed.query)
            changed = False
            for bad_param in ['pgbouncer', 'options']:
                if bad_param in qs:
                    qs.pop(bad_param)
                    changed = True
            
            # psycopg2 requires SSL to connect to Supabase
            if 'sslmode' not in qs:
                qs['sslmode'] = ['require']
                changed = True

            # If connecting to Supabase pooler in session mode (port 5432 or default),
            # switch to port 6543 (transaction mode). Session mode has a hard limit of
            # 15 concurrent clients across all processes (causing EMAXCONNSESSION),
            # whereas transaction mode multiplexes connections and supports high concurrency.
            if parsed.hostname and "pooler.supabase.com" in parsed.hostname:
                if parsed.port == 5432 or parsed.port is None:
                    netloc = parsed.netloc
                    if "@" in netloc:
                        user_pass, host_part = netloc.rsplit("@", 1)
                        host = host_part.split(":")[0]
                        netloc = f"{user_pass}@{host}:6543"
                    else:
                        host = netloc.split(":")[0]
                        netloc = f"{host}:6543"
                    parsed = parsed._replace(netloc=netloc)
                    changed = True
                
            if changed:
                url = urlunparse(parsed._replace(query=urlencode(qs, doseq=True)))
        except Exception:
            pass

    return url


def is_postgres():
    """Returns True if DATABASE_URL is configured and available."""
    return bool(get_database_url())


def resolve_sqlite_path():
    """Resolves local SQLite database path with persistent directory support."""
    if os.environ.get("CYBERSHIELD_DB_PATH"):
        return os.environ.get("CYBERSHIELD_DB_PATH")
    for persistent_dir in ["/var/data", "/data", "/persistent"]:
        if os.path.isdir(persistent_dir) and os.access(persistent_dir, os.W_OK):
            return os.path.join(persistent_dir, "cybershield.db")
    if os.environ.get("VERCEL"):
        tmp_db = os.path.join("/tmp", "cybershield.db")
        local_db = os.path.join(BASE_DIR, "cybershield.db")
        if not os.path.exists(tmp_db) and os.path.exists(local_db):
            import shutil
            try:
                shutil.copyfile(local_db, tmp_db)
            except Exception:
                pass
        return tmp_db
    return os.path.join(BASE_DIR, "cybershield.db")


class DbRow(Mapping):
    """
    Case-insensitive, dict-accessible, tuple-accessible row wrapper.
    100% compatible with sqlite3.Row and RealDictRow.
    """
    def __init__(self, description, values):
        self._values = tuple(values) if values is not None else ()
        self._keys = [d[0] for d in description] if description else []
        self._key_map = {k.lower(): i for i, k in enumerate(self._keys)}

    def __getitem__(self, item):
        if isinstance(item, int):
            return self._values[item]
        if isinstance(item, slice):
            return self._values[item]
        if isinstance(item, str):
            idx = self._key_map.get(item.lower())
            if idx is not None:
                return self._values[idx]
            raise KeyError(f"Column '{item}' not found in row. Available columns: {self._keys}")
        raise TypeError(f"Row indices must be integers or strings, not {type(item).__name__}")

    def __iter__(self):
        return iter(self._keys)

    def __len__(self):
        return len(self._values)

    def keys(self):
        return list(self._keys)

    def values(self):
        return list(self._values)

    def items(self):
        return list(zip(self._keys, self._values))

    def get(self, key, default=None):
        if isinstance(key, str):
            idx = self._key_map.get(key.lower())
            if idx is not None:
                return self._values[idx]
        return default

    def __contains__(self, item):
        if isinstance(item, str):
            return item.lower() in self._key_map
        return False

    def __repr__(self):
        d = dict(zip(self._keys, self._values))
        return f"<DbRow {d!r}>"

    def __eq__(self, other):
        if isinstance(other, DbRow):
            return self._values == other._values and self._keys == other._keys
        if isinstance(other, dict):
            return dict(self.items()) == other
        if isinstance(other, (tuple, list)):
            return self._values == tuple(other)
        return False


def translate_sql_for_postgres(sql):
    """
    Translates SQLite dialect queries into PostgreSQL compatible SQL:
    - Replaces parameter placeholder '?' with '%s' (outside string literals).
    - Translates PRAGMA journal_mode into harmless no-op.
    - Translates PRAGMA table_info(...) to information_schema query.
    - Translates sqlite_master to information_schema.tables.
    - Translates INSERT OR IGNORE to ON CONFLICT DO NOTHING.
    - Translates INTEGER PRIMARY KEY AUTOINCREMENT to SERIAL PRIMARY KEY.
    - Translates datetime('now') and date('now') to CURRENT_TIMESTAMP / CURRENT_DATE.
    - Adds RETURNING id to simple INSERT statements to capture cursor.lastrowid.
    """
    s = sql.strip()
    if not s:
        return "", False

    # Handle PRAGMA journal_mode
    if re.match(r"^PRAGMA\s+journal_mode", s, re.IGNORECASE):
        return "SELECT 1", False

    # Handle PRAGMA table_info
    pragma_match = re.match(r"^PRAGMA\s+table_info\s*\(\s*['\"]?(\w+)['\"]?\s*\)", s, re.IGNORECASE)
    if pragma_match:
        tbl = pragma_match.group(1).lower()
        return f"""
            SELECT 
                ordinal_position - 1 AS cid,
                column_name AS name,
                data_type AS type,
                CASE WHEN is_nullable = 'NO' THEN 1 ELSE 0 END AS notnull,
                column_default AS dflt_value,
                CASE WHEN column_name = 'id' OR column_name = 'query' THEN 1 ELSE 0 END AS pk
            FROM information_schema.columns 
            WHERE table_schema = 'public' AND LOWER(table_name) = '{tbl}'
            ORDER BY ordinal_position
        """, False

    # Handle sqlite_master
    s = re.sub(
        r"FROM\s+sqlite_master\s+WHERE\s+type\s*=\s*'table'",
        "FROM information_schema.tables WHERE table_schema = 'public'",
        s,
        flags=re.IGNORECASE
    )
    s = re.sub(
        r"FROM\s+sqlite_master",
        "FROM information_schema.tables WHERE table_schema = 'public'",
        s,
        flags=re.IGNORECASE
    )

    # Handle SQLite datetime functions
    s = re.sub(r"datetime\s*\(\s*'now'\s*,\s*'-(\d+)\s+days?'\s*\)", r"(NOW() - INTERVAL '\1 days')", s, flags=re.IGNORECASE)
    s = re.sub(r"datetime\s*\(\s*'now'\s*\)", "CURRENT_TIMESTAMP", s, flags=re.IGNORECASE)
    s = re.sub(r"date\s*\(\s*'now'\s*\)", "CURRENT_DATE", s, flags=re.IGNORECASE)

    # Handle SQLite IFNULL / NVL functions
    s = re.sub(r"\bIFNULL\s*\(", "COALESCE(", s, flags=re.IGNORECASE)
    s = re.sub(r"\bNVL\s*\(", "COALESCE(", s, flags=re.IGNORECASE)

    # Handle AUTOINCREMENT in DDL
    s = re.sub(r"INTEGER\s+PRIMARY\s+KEY\s+AUTOINCREMENT", "SERIAL PRIMARY KEY", s, flags=re.IGNORECASE)

    # Handle INSERT OR IGNORE
    if re.match(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+", s, re.IGNORECASE):
        s = re.sub(r"^\s*INSERT\s+OR\s+IGNORE\s+INTO\s+", "INSERT INTO ", s, flags=re.IGNORECASE)
        if "ON CONFLICT" not in s.upper():
            s = s.rstrip(" ;") + " ON CONFLICT DO NOTHING"

    # Replace ? with %s outside string literals, and escape % to %%
    parts = []
    in_quotes = False
    quote_char = None
    i = 0
    while i < len(s):
        c = s[i]
        if in_quotes:
            if c == '%':
                parts.append('%%')
            else:
                parts.append(c)
            if c == quote_char:
                if i + 1 < len(s) and s[i + 1] == quote_char:
                    parts.append(s[i + 1])
                    i += 1
                else:
                    in_quotes = False
        else:
            if c in ("'", '"'):
                in_quotes = True
                quote_char = c
                parts.append(c)
            elif c == '?':
                parts.append('%s')
            elif c == '%':
                parts.append('%%')
            else:
                parts.append(c)
        i += 1
    
    translated = "".join(parts)
    is_insert = bool(re.match(r"^\s*INSERT\s+INTO\s+", translated, re.IGNORECASE))
    has_returning = bool(re.search(r"\sRETURNING\s+", translated, re.IGNORECASE))
    
    # Auto-add RETURNING id for lastrowid capture if appropriate
    auto_returned_id = False
    if is_insert and not has_returning and "ON CONFLICT DO NOTHING" not in translated.upper():
        translated = translated.rstrip(" ;") + " RETURNING id"
        auto_returned_id = True

    return translated, auto_returned_id


class PostgresCursorWrapper:
    """Cursor wrapper for PostgreSQL connections that supports sqlite3 parameter styles and row returns."""
    def __init__(self, pg_cursor):
        self._cursor = pg_cursor
        self.lastrowid = None

    def execute(self, sql, params=None):
        translated_sql, auto_returned_id = translate_sql_for_postgres(sql)
        if params is not None:
            if isinstance(params, (list, tuple)):
                self._cursor.execute(translated_sql, params)
            elif isinstance(params, dict):
                self._cursor.execute(translated_sql, params)
            else:
                self._cursor.execute(translated_sql, (params,))
        else:
            self._cursor.execute(translated_sql)

        if auto_returned_id:
            try:
                row = self._cursor.fetchone()
                if row:
                    self.lastrowid = row[0]
            except Exception:
                pass
        return self

    def executemany(self, sql, param_list):
        translated_sql, _ = translate_sql_for_postgres(sql)
        self._cursor.executemany(translated_sql, param_list)
        return self

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        return DbRow(self._cursor.description, row)

    def fetchall(self):
        rows = self._cursor.fetchall()
        if not rows:
            return []
        desc = self._cursor.description
        return [DbRow(desc, r) for r in rows]

    def fetchmany(self, size=None):
        rows = self._cursor.fetchmany(size) if size else self._cursor.fetchmany()
        if not rows:
            return []
        desc = self._cursor.description
        return [DbRow(desc, r) for r in rows]

    @property
    def description(self):
        return self._cursor.description

    @property
    def rowcount(self):
        return self._cursor.rowcount

    def close(self):
        self._cursor.close()

    def __iter__(self):
        return self

    def __next__(self):
        row = self.fetchone()
        if row is None:
            raise StopIteration
        return row


import threading

_PG_POOL = None
_PG_POOL_LOCK = threading.Lock()


def _get_pg_pool():
    """Returns the singleton ThreadedConnectionPool for PostgreSQL connections."""
    global _PG_POOL
    if _PG_POOL is not None:
        return _PG_POOL

    with _PG_POOL_LOCK:
        if _PG_POOL is not None:
            return _PG_POOL
        db_url = get_database_url()
        if not db_url:
            return None
        try:
            from psycopg2.pool import ThreadedConnectionPool
            # maxconn=4 per worker prevents exceeding Supabase pooler connection quotas
            _PG_POOL = ThreadedConnectionPool(minconn=1, maxconn=4, dsn=db_url, connect_timeout=5)
            return _PG_POOL
        except Exception as e:
            print(f"[DB_ENGINE] Warning: could not initialize ThreadedConnectionPool: {e}")
            return None


def _check_pg_conn_alive(raw_conn):
    """Performs a lightweight sanity check to verify connection is open and ready."""
    try:
        if raw_conn.closed != 0:
            return False
        # Fast query to verify backend connection hasn't been dropped by server/pooler
        with raw_conn.cursor() as cur:
            cur.execute("SELECT 1")
        return True
    except Exception:
        return False


def _get_pooled_pg_conn():
    """Acquires an active, verified connection from the pool, re-creating if stale."""
    import time
    pool = _get_pg_pool()
    db_url = get_database_url()
    if pool:
        for _ in range(10):
            try:
                conn = pool.getconn()
                try:
                    conn.rollback()
                except Exception:
                    pass
                try:
                    conn.autocommit = True
                except Exception:
                    pass

                if not _check_pg_conn_alive(conn):
                    try:
                        pool.putconn(conn, close=True)
                    except Exception:
                        pass
                    conn = pool.getconn()
                    try:
                        conn.rollback()
                    except Exception:
                        pass
                    try:
                        conn.autocommit = True
                    except Exception:
                        pass

                return conn, pool
            except Exception:
                time.sleep(0.05)

    # Fallback to direct connection if pool is exhausted or unavailable
    import psycopg2
    raw_conn = psycopg2.connect(db_url, connect_timeout=5)
    raw_conn.autocommit = True
    return raw_conn, None


def _release_pooled_pg_conn(raw_conn, pool, force_close=False):
    """Returns connection to pool or closes it cleanly."""
    if not raw_conn:
        return
    if pool:
        try:
            if force_close or raw_conn.closed != 0:
                pool.putconn(raw_conn, close=True)
            else:
                try:
                    raw_conn.rollback()
                except Exception:
                    pass
                pool.putconn(raw_conn)
            return
        except Exception:
            pass
    try:
        raw_conn.close()
    except Exception:
        pass


class PostgresConnectionWrapper:
    """Connection wrapper for PostgreSQL providing sqlite3-compatible interface."""
    def __init__(self, pg_conn, pool=None, is_request_scoped=False):
        self._conn = pg_conn
        self._pool = pool
        self._is_request_scoped = is_request_scoped
        self._closed = False
        self.row_factory = None

    def __del__(self):
        try:
            self.close()
        except Exception:
            pass

    def cursor(self):
        return PostgresCursorWrapper(self._conn.cursor())

    def execute(self, sql, params=None):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def executemany(self, sql, param_list):
        cur = self.cursor()
        cur.executemany(sql, param_list)
        return cur

    def commit(self):
        try:
            if not self._conn.autocommit:
                self._conn.commit()
        except Exception:
            pass

    def rollback(self):
        try:
            if not self._conn.autocommit:
                self._conn.rollback()
        except Exception:
            pass

    def close(self):
        # In request-scoped mode, .close() during the request is a no-op;
        # the connection is closed/returned once at teardown_appcontext.
        if self._is_request_scoped:
            return

        if not self._closed:
            self._closed = True
            _release_pooled_pg_conn(self._conn, self._pool)

    def force_close(self):
        """Used by request teardown to return request-scoped connection to pool."""
        if not self._closed:
            self._closed = True
            _release_pooled_pg_conn(self._conn, self._pool)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()
        self.close()


class SQLiteConnectionProxy:
    """Proxy for SQLite connection during request scope to avoid premature close."""
    def __init__(self, real_conn, is_request_scoped=False):
        self._conn = real_conn
        self._is_request_scoped = is_request_scoped
        self.row_factory = real_conn.row_factory

    def cursor(self):
        return self._conn.cursor()

    def execute(self, *args, **kwargs):
        return self._conn.execute(*args, **kwargs)

    def executemany(self, *args, **kwargs):
        return self._conn.executemany(*args, **kwargs)

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        if self._is_request_scoped:
            return
        try:
            self._conn.close()
        except Exception:
            pass

    def force_close(self):
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)


def close_request_db_connection(exception=None):
    """Teardown handler to return any request-scoped database connection."""
    try:
        from flask import has_request_context, g
        if has_request_context():
            conn = getattr(g, "_csa_db_conn", None)
            if conn:
                g._csa_db_conn = None
                if hasattr(conn, "force_close"):
                    conn.force_close()
                else:
                    try:
                        conn.close()
                    except Exception:
                        pass
    except Exception:
        pass


def register_db_teardown(app):
    """Registers connection teardown on the Flask app."""
    app.teardown_appcontext(close_request_db_connection)


def get_db_connection():
    """
    Returns an active database connection:
    - If in a Flask request context: reuses request-scoped connection via g.
    - If DATABASE_URL is set: acquires pooled PostgreSQL connection.
    - Otherwise: connects to local SQLite with sqlite3.Row.
    """
    # 1. Check for active Flask request context to reuse connection
    try:
        from flask import has_request_context, g
        if has_request_context():
            cached = getattr(g, "_csa_db_conn", None)
            if cached is not None:
                # Verify connection is still open
                is_alive = True
                if isinstance(cached, PostgresConnectionWrapper):
                    if cached._conn.closed != 0:
                        is_alive = False
                if is_alive:
                    return cached
    except Exception:
        pass

    db_url = get_database_url()
    if db_url:
        raw_conn, pool = _get_pooled_pg_conn()
        in_request = False
        try:
            from flask import has_request_context, g
            in_request = has_request_context()
        except Exception:
            in_request = False

        conn = PostgresConnectionWrapper(raw_conn, pool=pool, is_request_scoped=in_request)
        if in_request:
            try:
                g._csa_db_conn = conn
            except Exception:
                pass
        return conn
    else:
        import sqlite3
        raw_sqlite = sqlite3.connect(resolve_sqlite_path())
        raw_sqlite.row_factory = sqlite3.Row

        in_request = False
        try:
            from flask import has_request_context, g
            in_request = has_request_context()
        except Exception:
            in_request = False

        conn = SQLiteConnectionProxy(raw_sqlite, is_request_scoped=in_request)
        if in_request:
            try:
                g._csa_db_conn = conn
            except Exception:
                pass
        return conn

