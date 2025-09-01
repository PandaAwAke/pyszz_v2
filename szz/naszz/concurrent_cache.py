from cachetools import TTLCache
import threading

class ConcurrentCache:

    def __init__(self, maxsize=100, ttl=600):
        self._cache = TTLCache(maxsize=maxsize, ttl=ttl)
        self._cache_lock = threading.Lock()

    def get(self, key):
        with self._cache_lock:
            return self._cache.get(key)

    def put(self, key, value):
        with self._cache_lock:
            self._cache[key] = value
    
    def get_or_put(self, key, value_generator):
        with self._cache_lock:
            if not self._cache.get(key):
                self._cache[key] = value_generator()
            return self._cache.get(key)
