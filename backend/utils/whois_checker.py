"""
PhishGuard — utils/whois_checker.py
Real-time WHOIS domain age lookup with in-memory LRU cache.

Spec (from report §4.4, §6.1):
  - Extracts registrable domain from URL
  - Checks 24-hour in-memory LRU cache first
  - On cache miss: dispatches python-whois query with 8-second timeout
  - Returns domain age in days (int) or None if lookup fails
  - Cache TTL: 24 hours (86400 seconds)
"""

import asyncio
import logging
import time
from functools import lru_cache
from typing import Optional
from datetime import datetime, timezone

import tldextract
import whois

logger = logging.getLogger("phishguard.whois")

WHOIS_TIMEOUT_SECS = 8
CACHE_TTL_SECS = 86400   # 24 hours


class TTLCache:
    """
    Simple thread-safe TTL cache.
    Stores (value, expiry_timestamp) tuples.
    """

    def __init__(self, max_size: int = 1000, ttl: int = CACHE_TTL_SECS):
        self._store: dict[str, tuple] = {}
        self._max_size = max_size
        self._ttl = ttl

    def get(self, key: str) -> Optional[int]:
        if key not in self._store:
            return None
        value, expiry = self._store[key]
        if time.monotonic() > expiry:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Optional[int]):
        # Simple eviction: remove expired entries when approaching max size
        if len(self._store) >= self._max_size:
            now = time.monotonic()
            expired = [k for k, (_, e) in self._store.items() if e < now]
            for k in expired[:100]:
                del self._store[k]
        self._store[key] = (value, time.monotonic() + self._ttl)

    def __len__(self) -> int:
        return len(self._store)


class WHOISChecker:
    """
    Domain age checker with TTL cache.

    Usage:
        checker = WHOISChecker()
        age_days = await checker.get_domain_age_async("https://example.com")
    """

    def __init__(self):
        self._cache = TTLCache(max_size=2000, ttl=CACHE_TTL_SECS)
        logger.info("WHOISChecker initialised with 24h TTL cache")

    def _extract_domain(self, url: str) -> str:
        """Extract registrable domain (e.g., 'example.com') from any URL."""
        try:
            ext = tldextract.extract(url)
            if ext.domain and ext.suffix:
                return f"{ext.domain}.{ext.suffix}"
        except Exception:
            pass
        return ""

    def _whois_lookup(self, domain: str) -> Optional[int]:
        """
        Synchronous WHOIS lookup. Returns domain age in days or None.
        Runs in a thread pool to avoid blocking the event loop.
        """
        try:
            result = whois.whois(domain)
            creation = result.get("creation_date")

            if creation is None:
                logger.debug(f"WHOIS: no creation_date for {domain}")
                return None

            # python-whois may return a list (some registrars return multiple dates)
            if isinstance(creation, list):
                creation = creation[0]

            # Ensure timezone-aware comparison
            if creation.tzinfo is None:
                creation = creation.replace(tzinfo=timezone.utc)

            now = datetime.now(timezone.utc)
            age_days = (now - creation).days
            return max(age_days, 0)   # Clamp to 0 for any clock skew

        except Exception as e:
            logger.debug(f"WHOIS lookup failed for {domain}: {e}")
            return None

    def get_domain_age(self, url: str) -> Optional[int]:
        """
        Synchronous domain age lookup with cache.
        Returns age in days or None.
        """
        domain = self._extract_domain(url)
        if not domain:
            return None

        # Cache hit
        cached = self._cache.get(domain)
        if cached is not None:
            logger.debug(f"WHOIS cache hit: {domain} = {cached} days")
            return cached

        # Cache miss → live lookup
        logger.debug(f"WHOIS cache miss: querying {domain}")
        age = self._whois_lookup(domain)
        self._cache.set(domain, age)

        if age is not None:
            logger.info(f"WHOIS: {domain} is {age} days old")
        else:
            logger.info(f"WHOIS: could not determine age for {domain}")

        return age

    async def get_domain_age_async(self, url: str) -> Optional[int]:
        """
        Async wrapper — runs synchronous WHOIS in thread pool.
        Enforces WHOIS_TIMEOUT_SECS timeout to protect API latency.
        """
        loop = asyncio.get_running_loop()
        try:
            result = await asyncio.wait_for(
                loop.run_in_executor(None, self.get_domain_age, url),
                timeout=WHOIS_TIMEOUT_SECS,
            )
            return result
        except asyncio.TimeoutError:
            domain = self._extract_domain(url)
            logger.warning(f"WHOIS timeout ({WHOIS_TIMEOUT_SECS}s) for {domain}")
            # Cache the timeout result so we don't retry within TTL
            self._cache.set(domain, None)
            return None
        except Exception as e:
            logger.error(f"Unexpected WHOIS error: {e}")
            return None

    @property
    def cache_size(self) -> int:
        return len(self._cache)
