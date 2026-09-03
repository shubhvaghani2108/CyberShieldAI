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


class PostgresConnectionWrapper:
    """Connection wrapper for PostgreSQL providing sqlite3-compatible interface."""
    def __init__(self, pg_conn):
        self._conn = pg_conn
        self.row_factory = None

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
        try:
            self._conn.close()
        except Exception:
            pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()


def get_db_connection():
    """
    Returns an active database connection:
    - If DATABASE_URL is set: connects to PostgreSQL and returns a PostgresConnectionWrapper.
    - Otherwise: connects to local SQLite and returns sqlite3.Connection with row_factory=sqlite3.Row.
    """
    db_url = get_database_url()
    if db_url:
        import psycopg2
        raw_conn = psycopg2.connect(db_url)
        raw_conn.autocommit = True
        return PostgresConnectionWrapper(raw_conn)
    else:
        import sqlite3
        conn = sqlite3.connect(resolve_sqlite_path())
        conn.row_factory = sqlite3.Row
        return conn
