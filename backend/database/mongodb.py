"""
PhishGuard — database/mongodb.py
MongoDB persistence layer via Motor (async driver).

Collections (from report §4.5):
  1. scans         — All scan results (audit log)
  2. threats       — Phishing-only subset (dashboard fast reads)
  3. bypasses      — User 'Proceed Anyway' override events
  4. false_positives — User-submitted false positive reports
  5. stats_hourly  — Pre-aggregated hourly counters (atomic $inc upsert)

Architecture:
  - Motor AsyncIOMotorClient for non-blocking async I/O
  - MongoDB Atlas (cloud) or local mongod
  - Graceful degradation: if MongoDB is unavailable, scans still complete
  - Stats are updated via atomic $inc to avoid race conditions
"""

import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Optional

logger = logging.getLogger("phishguard.mongodb")

# ─────────────────────────────────────────────
# Configuration (from environment variables)
# ─────────────────────────────────────────────
MONGO_URI      = os.getenv("MONGODB_URI", "mongodb://localhost:27017")
DB_NAME        = os.getenv("MONGODB_DB",  "phishguard")

# Collection names
COL_SCANS      = "scans"
COL_THREATS    = "threats"
COL_BYPASSES   = "bypasses"
COL_FP         = "false_positives"
COL_STATS      = "stats_hourly"


class MongoDBLogger:
    """
    Async MongoDB logger for all PhishGuard persistence operations.

    Usage:
        logger = MongoDBLogger()
        await logger.connect()
        await logger.log_scan(response_dict, dom_text_snippet)
        await logger.close()
    """

    def __init__(self):
        self._client = None
        self._db = None
        self._connected = False

    async def connect(self):
        """Establish async connection to MongoDB. Fails gracefully."""
        try:
            from motor.motor_asyncio import AsyncIOMotorClient
            self._client = AsyncIOMotorClient(
                MONGO_URI,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=5000,
            )
            # Verify connection
            await self._client.admin.command("ping")
            self._db = self._client[DB_NAME]
            self._connected = True

            # Ensure indexes exist
            await self._create_indexes()
            logger.info(f"✅ MongoDB connected: {DB_NAME} @ {MONGO_URI[:40]}...")

        except Exception as e:
            self._connected = False
            logger.warning(
                f"⚠️  MongoDB connection failed: {e}. "
                "Detection will continue — threat logging disabled."
            )

    async def close(self):
        if self._client:
            self._client.close()
            logger.info("MongoDB connection closed.")

    async def _create_indexes(self):
        """Create indexes for common query patterns."""
        try:
            # scans: sort by timestamp desc, filter by status
            await self._db[COL_SCANS].create_index([("timestamp", -1)])
            await self._db[COL_SCANS].create_index([("status", 1), ("timestamp", -1)])
            await self._db[COL_SCANS].create_index([("url", 1)])

            # threats: fast dashboard queries
            await self._db[COL_THREATS].create_index([("timestamp", -1)])
            await self._db[COL_THREATS].create_index([("primary_vector", 1)])

            # stats_hourly: unique bucket per hour
            await self._db[COL_STATS].create_index([("bucket", 1)], unique=True)

            # false_positives: pending review filter
            await self._db[COL_FP].create_index([("reviewed", 1), ("timestamp", -1)])

            logger.info("MongoDB indexes ensured.")
        except Exception as e:
            logger.warning(f"Index creation warning: {e}")

    # ─────────────────────────────────────────────
    # Core: log a scan result
    # ─────────────────────────────────────────────
    async def log_scan(self, response: dict, dom_text_snippet: str = ""):
        """
        Persist a scan result to the scans collection.
        If phishing, also write a denormalised document to threats collection.
        Always updates the stats_hourly atomic counter.
        """
        if not self._connected:
            return

        try:
            now = datetime.now(timezone.utc)
            doc = {
                "url":              response.get("url"),
                "status":           response.get("status"),
                "trust_score":      response.get("trust_score"),
                "phishing_probability": response.get("phishing_probability"),
                "nlp_phishing_prob":    response.get("nlp_phishing_prob"),
                "cnn_phishing_prob":    response.get("cnn_phishing_prob"),
                "url_risk_score":       response.get("url_risk_score"),
                "whois_domain_age_days": response.get("whois_domain_age_days"),
                "threat_dna":       response.get("threat_dna"),
                "primary_vector":   response.get("primary_vector"),
                "latency_ms":       response.get("latency_ms"),
                "dom_text_snippet": dom_text_snippet,  # Never store full DOM text (privacy)
                "timestamp":        now,
            }

            await self._db[COL_SCANS].insert_one(doc)

            # Phishing-only denormalised collection for fast dashboard reads
            if response.get("status") == "phishing":
                threat_doc = {
                    "url":             doc["url"],
                    "trust_score":     doc["trust_score"],
                    "primary_vector":  doc["primary_vector"],
                    "whois_age_days":  doc["whois_domain_age_days"],
                    "nlp_prob":        doc["nlp_phishing_prob"],
                    "cnn_prob":        doc["cnn_phishing_prob"],
                    "timestamp":       now,
                }
                await self._db[COL_THREATS].insert_one(threat_doc)

            # Atomic hourly stats update
            await self._increment_hourly_stats(now, is_phishing=response.get("status") == "phishing",
                                               latency_ms=response.get("latency_ms", 0))

        except Exception as e:
            logger.error(f"log_scan error: {e}")

    # ─────────────────────────────────────────────
    # Bypass logging (user clicked "Proceed Anyway")
    # ─────────────────────────────────────────────
    async def log_bypass(self, url: str, trust_score: float):
        if not self._connected:
            return
        try:
            await self._db[COL_BYPASSES].insert_one({
                "url":         url,
                "trust_score": trust_score,
                "timestamp":   datetime.now(timezone.utc),
            })
        except Exception as e:
            logger.error(f"log_bypass error: {e}")

    # ─────────────────────────────────────────────
    # False positive reporting
    # ─────────────────────────────────────────────
    async def log_false_positive(self, url: str, user_comment: str = ""):
        if not self._connected:
            return
        try:
            await self._db[COL_FP].insert_one({
                "url":          url,
                "user_comment": user_comment[:500],   # Limit comment length
                "reviewed":     False,
                "timestamp":    datetime.now(timezone.utc),
            })
        except Exception as e:
            logger.error(f"log_false_positive error: {e}")

    # ─────────────────────────────────────────────
    # Atomic hourly stats ($inc upsert)
    # ─────────────────────────────────────────────
    async def _increment_hourly_stats(self, now: datetime, is_phishing: bool, latency_ms: int):
        """
        Atomically increment hourly counters using $inc upsert.
        Bucket key = ISO hour string: '2025-01-15T14' (UTC).
        """
        try:
            bucket = now.strftime("%Y-%m-%dT%H")
            inc = {
                "total_scans": 1,
                "latency_sum": latency_ms,
            }
            if is_phishing:
                inc["phishing"] = 1

            await self._db[COL_STATS].update_one(
                {"bucket": bucket},
                {"$inc": inc, "$setOnInsert": {"bucket": bucket}},
                upsert=True,
            )
        except Exception as e:
            logger.error(f"stats increment error: {e}")

    # ─────────────────────────────────────────────
    # Dashboard stats
    # ─────────────────────────────────────────────
    async def get_dashboard_stats(self) -> dict:
        """
        Return aggregate stats for the analytics dashboard.
        Covers the last 24 hours from hourly stats collection.
        """
        if not self._connected:
            return {"error": "MongoDB unavailable", "connected": False}

        try:
            now = datetime.now(timezone.utc)
            cutoff = now - timedelta(hours=24)

            # Total scans (all time)
            total_scans = await self._db[COL_SCANS].count_documents({})

            # Phishing blocked (all time)
            total_blocked = await self._db[COL_THREATS].count_documents({})

            # Last 24h stats from pre-aggregated collection
            buckets = []
            cutoff_str = cutoff.strftime("%Y-%m-%dT%H")
            async for doc in self._db[COL_STATS].find(
                {"bucket": {"$gte": cutoff_str}},
                sort=[("bucket", 1)]
            ):
                buckets.append({
                    "hour":         doc["bucket"],
                    "total_scans":  doc.get("total_scans", 0),
                    "phishing":     doc.get("phishing", 0),
                    "avg_latency":  round(
                        doc.get("latency_sum", 0) / max(doc.get("total_scans", 1), 1)
                    ),
                })

            # Recent threats (last 20)
            recent_threats = []
            async for doc in self._db[COL_THREATS].find(
                {},
                {"_id": 0, "url": 1, "trust_score": 1, "primary_vector": 1,
                 "whois_age_days": 1, "timestamp": 1},
                sort=[("timestamp", -1)],
                limit=20,
            ):
                doc["timestamp"] = doc["timestamp"].isoformat()
                recent_threats.append(doc)

            # Pending false positive reports
            pending_fp = await self._db[COL_FP].count_documents({"reviewed": False})

            # Average trust score (last 1000 scans)
            pipeline = [
                {"$sort": {"timestamp": -1}},
                {"$limit": 1000},
                {"$group": {"_id": None, "avg_trust": {"$avg": "$trust_score"}}},
            ]
            avg_cursor = self._db[COL_SCANS].aggregate(pipeline)
            avg_doc = await avg_cursor.to_list(length=1)
            avg_trust_score = round(avg_doc[0]["avg_trust"], 3) if avg_doc else 0.0

            return {
                "connected":         True,
                "total_scans":       total_scans,
                "total_blocked":     total_blocked,
                "avg_trust_score":   avg_trust_score,
                "pending_fp_reports": pending_fp,
                "hourly_activity":   buckets,
                "recent_threats":    recent_threats,
            }

        except Exception as e:
            logger.error(f"get_dashboard_stats error: {e}")
            return {"error": str(e), "connected": True}
