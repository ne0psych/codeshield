"""
LRU Cache for Database Query Results

Thread-safe Least Recently Used cache for frequently accessed database
query results during a scan session. Avoids redundant SQLite reads when
multiple files reference the same package or rule data.

Uses OrderedDict for O(1) get/put with LRU eviction.
"""

import threading
from collections import OrderedDict
from typing import Any, Optional, Hashable


class LRUCache:
    """
    Thread-safe LRU cache with configurable capacity.

    Get/Put: O(1) amortized via OrderedDict
    Eviction: automatic when capacity exceeded, removes least recently used
    """

    def __init__(self, capacity: int = 1024):
        if capacity < 1:
            raise ValueError("Cache capacity must be >= 1")
        self._capacity = capacity
        self._cache: OrderedDict = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def get(self, key: Hashable) -> Optional[Any]:
        """
        Get a cached value. Returns None on miss.
        Moves accessed item to most-recently-used position.
        """
        with self._lock:
            if key in self._cache:
                # Move to end (most recently used)
                self._cache.move_to_end(key)
                self._hits += 1
                return self._cache[key]
            self._misses += 1
            return None

    def put(self, key: Hashable, value: Any) -> None:
        """
        Store a value. Evicts least recently used item if at capacity.
        """
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                self._cache[key] = value
            else:
                if len(self._cache) >= self._capacity:
                    # Evict LRU item (first item in OrderedDict)
                    self._cache.popitem(last=False)
                self._cache[key] = value

    def invalidate(self, key: Hashable) -> None:
        """Remove a specific key from the cache."""
        with self._lock:
            self._cache.pop(key, None)

    def clear(self) -> None:
        """Clear all cached entries."""
        with self._lock:
            self._cache.clear()
            self._hits = 0
            self._misses = 0

    @property
    def size(self) -> int:
        return len(self._cache)

    @property
    def hit_rate(self) -> float:
        total = self._hits + self._misses
        return self._hits / total if total > 0 else 0.0

    @property
    def stats(self) -> dict:
        return {
            "size": self.size,
            "capacity": self._capacity,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": f"{self.hit_rate:.1%}"
        }
