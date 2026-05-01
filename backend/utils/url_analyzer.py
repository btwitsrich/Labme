"""
PhishGuard — utils/url_analyzer.py
URL lexical and structural feature extraction.

Based on:
  - Mohammad et al. (2014): 30 URL lexical + host features
  - Sahingoz et al. (2019): TLD-based and brand-keyword features
  - PhishGuard report Chapter 6: URL Risk axis of Threat DNA

Extracted features feed both the ensemble scorer and the XAI explainer.
"""

import ipaddress
import logging
import re
import string
from urllib.parse import urlparse

import tldextract

logger = logging.getLogger("phishguard.url")

# ─────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────
SHORTENING_SERVICES = re.compile(
    r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl"
    r"|tr\.im|is\.gd|cli\.gs|yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu"
    r"|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|short\.to|BudURL\.com|ping\.fm"
    r"|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|doiop\.com"
    r"|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|lnkd\.in"
    r"|db\.tt|qr\.ae|adf\.ly|bitly\.com|cur\.lv|ity\.im|q\.gs|po\.st|bc\.vc"
    r"|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|prettylinkpro\.com"
    r"|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd"
    r"|link\.zip\.net",
    re.IGNORECASE,
)

HIGH_RISK_TLDS = {
    ".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw",
    ".cc", ".icu", ".buzz", ".cyou", ".fun", ".monster", ".cfd",
}

KNOWN_BRANDS = {
    "paypal", "apple", "google", "microsoft", "amazon", "netflix",
    "facebook", "instagram", "twitter", "linkedin", "dropbox", "adobe",
    "bankofamerica", "chase", "wellsfargo", "citibank", "hsbc", "barclays",
    "hdfc", "sbi", "icici", "paytm", "coinbase", "binance", "metamask",
    "steam", "ebay", "alibaba", "flipkart", "walmart", "target",
}

SUSPICIOUS_PATH_TERMS = re.compile(
    r"login|signin|sign-in|verify|secure|account|update|confirm"
    r"|banking|wallet|credential|password|recover|validate|auth",
    re.IGNORECASE,
)

SPECIAL_CHARS = set("@~`!$%&")


class URLAnalyzer:
    """
    Extracts a feature dict from any URL.
    All methods are synchronous (URL analysis is fast enough for the event loop).
    """

    def extract_features(self, url: str) -> dict:
        """
        Main entry point. Returns a feature dict including a computed risk_score.
        """
        try:
            parsed = urlparse(url)
            ext = tldextract.extract(url)
        except Exception as e:
            logger.error(f"URL parse error for '{url[:80]}': {e}")
            return self._default_features()

        features = {}

        # ── 1. IP address instead of hostname ──────────────────────────────
        features["has_ip_address"] = self._has_ip(parsed.netloc)

        # ── 2. Special characters (@ in URL = redirect trick) ──────────────
        features["has_special_chars"] = any(c in url for c in SPECIAL_CHARS)

        # ── 3. URL length ──────────────────────────────────────────────────
        features["url_length"] = len(url)

        # ── 4. Path depth (/ count) ────────────────────────────────────────
        features["path_depth"] = len([p for p in parsed.path.split("/") if p])

        # ── 5. Redirect pattern (// after protocol) ────────────────────────
        features["has_redirect"] = self._has_redirect(url)

        # ── 6. HTTPS in domain part (not protocol) ─────────────────────────
        features["https_in_domain"] = "https" in parsed.netloc.lower()

        # ── 7. URL shortener ───────────────────────────────────────────────
        features["is_shortened"] = bool(SHORTENING_SERVICES.search(url))

        # ── 8. Hyphens in domain ───────────────────────────────────────────
        features["hyphen_count"] = ext.domain.count("-")

        # ── 9. TLD risk ────────────────────────────────────────────────────
        tld = f".{ext.suffix}" if ext.suffix else ""
        features["tld"] = tld
        features["high_risk_tld"] = tld in HIGH_RISK_TLDS

        # ── 10. Brand keyword in subdomain ─────────────────────────────────
        features["brand_in_subdomain"] = self._brand_in_subdomain(ext)

        # ── 11. Suspicious path terms ──────────────────────────────────────
        features["suspicious_path"] = bool(SUSPICIOUS_PATH_TERMS.search(parsed.path))

        # ── 12. Domain length ──────────────────────────────────────────────
        features["domain_length"] = len(ext.domain)

        # ── 13. Subdomain depth ────────────────────────────────────────────
        features["subdomain_depth"] = (
            len(ext.subdomain.split(".")) if ext.subdomain else 0
        )

        # ── 14. Uses HTTP (not HTTPS) ──────────────────────────────────────
        features["no_https"] = not url.startswith("https://")

        # ── 15. SSL risk proxy ─────────────────────────────────────────────
        features["ssl_risk"] = self._compute_ssl_risk(url, features)

        # ── Computed risk score ────────────────────────────────────────────
        features["risk_score"] = self._compute_risk_score(features)

        return features

    # ─────────────────────────────────────────────
    # Feature helpers
    # ─────────────────────────────────────────────
    def _has_ip(self, netloc: str) -> bool:
        """Check if the host portion is an IP address."""
        # Remove port if present
        host = netloc.split(":")[0].strip("[]")
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _has_redirect(self, url: str) -> bool:
        """Check for // after the protocol section — indicates redirect."""
        pos = url.rfind("//")
        return pos > 7   # Beyond the 'https://' prefix

    def _brand_in_subdomain(self, ext) -> str:
        """
        Check if a known brand name appears in the subdomain but NOT in the domain.
        E.g., 'paypal.secure-verify.com' → returns 'paypal'
        """
        subdomain = ext.subdomain.lower()
        domain    = ext.domain.lower()
        for brand in KNOWN_BRANDS:
            if brand in subdomain and brand not in domain:
                return brand
        return ""

    def _compute_ssl_risk(self, url: str, features: dict) -> float:
        """
        Heuristic SSL risk score based on URL features.
        Full SSL cert validation requires a live TLS handshake (out of scope here).
        """
        score = 0.0
        if features["no_https"]:
            score += 0.6
        if features["has_ip_address"]:
            score += 0.2
        if features["high_risk_tld"]:
            score += 0.15
        return min(score, 1.0)

    def _compute_risk_score(self, features: dict) -> float:
        """
        Weighted URL risk score in [0.0, 1.0].
        Weights calibrated against Sahingoz et al. (2019) feature importances.
        """
        score = 0.0

        if features["has_ip_address"]:          score += 0.30
        if features["is_shortened"]:            score += 0.20
        if features["brand_in_subdomain"]:      score += 0.25
        if features["no_https"]:                score += 0.15
        if features["high_risk_tld"]:           score += 0.20
        if features["has_redirect"]:            score += 0.10
        if features["has_special_chars"]:       score += 0.10
        if features["hyphen_count"] >= 3:       score += 0.10
        if features["url_length"] > 100:        score += 0.05
        if features["url_length"] > 200:        score += 0.05
        if features["subdomain_depth"] >= 3:    score += 0.10
        if features["suspicious_path"]:         score += 0.05
        if features["domain_length"] < 4:       score += 0.05

        return round(min(score, 1.0), 4)

    def _default_features(self) -> dict:
        """Safe fallback feature dict for unparseable URLs."""
        return {
            "has_ip_address": False,
            "has_special_chars": False,
            "url_length": 0,
            "path_depth": 0,
            "has_redirect": False,
            "https_in_domain": False,
            "is_shortened": False,
            "hyphen_count": 0,
            "tld": "",
            "high_risk_tld": False,
            "brand_in_subdomain": "",
            "suspicious_path": False,
            "domain_length": 0,
            "subdomain_depth": 0,
            "no_https": True,
            "ssl_risk": 0.5,
            "risk_score": 0.5,
        }
