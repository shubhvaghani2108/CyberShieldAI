"""
CyberShieldAI - High-Performance In-Memory Context Cache
=========================================================
Thread-safe, TTL-based caching layer for dashboard routes and scan contexts.
Eliminates redundant round-trips to remote databases during user navigation.

Key guarantees:
- Strict user isolation: Cache entries are partitioned by user_id.
- Automatic invalidation: Cache is wiped for a user whenever a new scan completes
  or monitoring configuration changes.
- Short TTL (default 30-45 seconds) ensures eventual consistency even if external writes occur.
- Zero modification to data structures or business logic.
"""

import threading
import time
from typing import Any, Optional


class FastContextCache:
    def __init__(self, default_ttl: int = 30):
        self._default_ttl = default_ttl
        self._cache = {}
        self._lock = threading.Lock()

    def _make_key(self, key: str, user_id: Optional[Any], extra: Optional[str] = None) -> str:
        u_part = f"u:{user_id}" if user_id is not None else "u:global"
        x_part = f":{extra}" if extra else ""
        return f"{u_part}:{key}{x_part}"

    def get(self, key: str, user_id: Optional[Any] = None, extra: Optional[str] = None) -> Optional[Any]:
        cache_key = self._make_key(key, user_id, extra)
        now = time.time()
        with self._lock:
            entry = self._cache.get(cache_key)
            if entry is not None:
                val, expires_at = entry
                if now < expires_at:
                    return val
                # Expired
                try:
                    del self._cache[cache_key]
                except KeyError:
                    pass
        return None

    def set(
        self,
        key: str,
        value: Any,
        user_id: Optional[Any] = None,
        extra: Optional[str] = None,
        ttl: Optional[int] = None,
    ) -> None:
        cache_key = self._make_key(key, user_id, extra)
        ttl_val = ttl if ttl is not None else self._default_ttl
        expires_at = time.time() + ttl_val
        with self._lock:
            self._cache[cache_key] = (value, expires_at)
            # Occasional eviction of expired keys if cache grows large
            if len(self._cache) > 200:
                self._prune_expired()

    def invalidate(self, user_id: Optional[Any] = None) -> None:
        """
        Invalidates cache.
        If user_id is provided, clears all entries for that user.
        If user_id is None, clears all cached entries across the entire app.
        """
        with self._lock:
            if user_id is None:
                self._cache.clear()
            else:
                prefix = f"u:{user_id}:"
                keys_to_del = [k for k in self._cache if k.startswith(prefix)]
                for k in keys_to_del:
                    del self._cache[k]

    def _prune_expired(self) -> None:
        now = time.time()
        expired_keys = [k for k, (_, exp) in self._cache.items() if exp <= now]
        for k in expired_keys:
            try:
                del self._cache[k]
            except KeyError:
                pass


# Global singleton cache instance
dashboard_cache = FastContextCache(default_ttl=30)
