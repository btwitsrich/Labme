"""
PhishGuard — models/xai_explainer.py
LIME-inspired Explainable AI for transparent phishing verdicts.

Approach (from report §2.5, §5.3):
  Ribeiro et al. (2016) LIME methodology adapted for phishing domain.
  Generates human-readable ExplanationCards across six threat axes:
    URL Risk, Visual Clone, NLP Urgency, Domain Age, SSL/TLS Risk, Brand Match

  Rather than fitting a local linear model (full LIME), we use a
  rule-based explanation engine that maps feature ranges to severity-weighted
  reason cards — computationally cheaper and more interpretable for users.
"""

import logging
import re
from typing import Optional

logger = logging.getLogger("phishguard.xai")

# ─────────────────────────────────────────────
# Severity thresholds
# ─────────────────────────────────────────────
HIGH_THRESHOLD   = 0.75
MEDIUM_THRESHOLD = 0.45


def _severity(score: float) -> str:
    if score >= HIGH_THRESHOLD:
        return "high"
    if score >= MEDIUM_THRESHOLD:
        return "medium"
    return "low"


# ─────────────────────────────────────────────
# Known brand domains for brand-match detection
# ─────────────────────────────────────────────
KNOWN_BRANDS = {
    "paypal", "apple", "google", "microsoft", "amazon", "netflix", "facebook",
    "instagram", "twitter", "linkedin", "dropbox", "adobe", "bankofamerica",
    "chase", "wellsfargo", "citibank", "hsbc", "barclays", "hdfc", "sbi",
    "icici", "paytm", "coinbase", "binance", "metamask", "steam",
}

URGENCY_KEYWORDS = [
    "verify", "account suspended", "urgent", "immediately", "click here",
    "confirm your", "limited time", "expires", "unauthorized", "security alert",
    "update required", "validate", "unusual activity", "locked", "suspend",
    "password", "login", "credential", "ssn", "social security", "credit card",
]


class XAIExplainer:
    """
    Generates ExplanationCard list for a PhishGuard scan result.
    Each card has: severity, icon, title, detail.
    """

    def generate_explanations(
        self,
        url: str,
        url_features: dict,
        nlp_prob: float,
        cnn_prob: float,
        whois_age_days: Optional[int],
        dom_text: str = "",
    ) -> list[dict]:
        """
        Returns up to 6 ExplanationCards sorted by severity (high → low).
        """
        cards = []

        cards.extend(self._explain_url(url, url_features))
        cards.extend(self._explain_nlp(nlp_prob, dom_text))
        cards.extend(self._explain_cnn(cnn_prob))
        cards.extend(self._explain_whois(whois_age_days))
        cards.extend(self._explain_ssl(url, url_features))

        # Sort: high → medium → low
        order = {"high": 0, "medium": 1, "low": 2}
        cards.sort(key=lambda c: order.get(c["severity"], 3))

        return cards[:6]   # Max 6 cards per report spec

    # ─────────────────────────────────────────────────────────────────────
    # URL-based explanations
    # ─────────────────────────────────────────────────────────────────────
    def _explain_url(self, url: str, features: dict) -> list[dict]:
        cards = []

        # IP address in URL
        if features.get("has_ip_address"):
            cards.append({
                "severity": "high",
                "icon": "🔢",
                "title": "IP address used instead of domain name",
                "detail": (
                    "Legitimate websites use registered domain names. "
                    "Using a raw IP address (e.g., http://192.168.1.1/login) "
                    "is a strong phishing indicator used to evade domain-based filters."
                ),
            })

        # Suspicious TLD
        suspicious_tlds = {".xyz", ".top", ".tk", ".ml", ".ga", ".cf", ".gq", ".pw", ".cc"}
        tld = features.get("tld", "")
        if tld in suspicious_tlds:
            cards.append({
                "severity": "high",
                "icon": "🌐",
                "title": f"High-risk top-level domain: {tld}",
                "detail": (
                    f"The domain uses '{tld}', which is disproportionately associated "
                    "with malicious activity due to low registration costs and minimal "
                    "identity verification requirements."
                ),
            })

        # Brand keyword in subdomain (e.g., paypal.malicious.com)
        brand_in_subdomain = features.get("brand_in_subdomain")
        if brand_in_subdomain:
            cards.append({
                "severity": "high",
                "icon": "🎭",
                "title": f"Brand name '{brand_in_subdomain}' found in subdomain",
                "detail": (
                    f"The URL contains the brand name '{brand_in_subdomain}' in a subdomain "
                    "rather than the registered domain. This is a classic spoofing technique: "
                    f"'secure-{brand_in_subdomain}.malicious.com' appears legitimate at a glance "
                    f"but the actual domain is not {brand_in_subdomain}."
                ),
            })

        # Excessive hyphens (e.g., secure-login-paypal-verify.com)
        if features.get("hyphen_count", 0) >= 3:
            cards.append({
                "severity": "medium",
                "icon": "➖",
                "title": "Excessive hyphens in domain name",
                "detail": (
                    f"The domain contains {features['hyphen_count']} hyphens. "
                    "Phishing domains frequently use hyphens to combine brand keywords "
                    "with deceptive terms (e.g., 'account-verify-secure-login.com')."
                ),
            })

        # URL length
        url_len = features.get("url_length", 0)
        if url_len > 100:
            cards.append({
                "severity": "medium",
                "icon": "📏",
                "title": "Unusually long URL",
                "detail": (
                    f"This URL is {url_len} characters long. "
                    "Abnormally long URLs are often used to obscure the true destination "
                    "or embed a legitimate-looking domain within a longer malicious path."
                ),
            })

        # Redirects / double-slash
        if features.get("has_redirect"):
            cards.append({
                "severity": "medium",
                "icon": "↪️",
                "title": "URL contains redirect pattern",
                "detail": (
                    "The URL contains a redirection construct (//) after the protocol section. "
                    "This is used to forward users from a seemingly trusted domain to a "
                    "malicious destination."
                ),
            })

        # URL shortener
        if features.get("is_shortened"):
            cards.append({
                "severity": "medium",
                "icon": "✂️",
                "title": "URL shortener detected",
                "detail": (
                    "This URL passes through a shortening service (bit.ly, tinyurl, etc.), "
                    "masking the true destination. Phishing campaigns routinely use URL "
                    "shorteners to bypass link-reputation filters."
                ),
            })

        return cards

    # ─────────────────────────────────────────────────────────────────────
    # NLP-based explanations
    # ─────────────────────────────────────────────────────────────────────
    def _explain_nlp(self, nlp_prob: float, dom_text: str) -> list[dict]:
        if nlp_prob < MEDIUM_THRESHOLD:
            return []

        cards = []
        text_lower = dom_text.lower()

        # Find triggered urgency keywords
        triggered = [kw for kw in URGENCY_KEYWORDS if kw in text_lower]

        if nlp_prob >= HIGH_THRESHOLD:
            detail = (
                f"The DistilBERT NLP model detected high-confidence phishing language patterns "
                f"(confidence: {nlp_prob:.0%}). "
            )
            if triggered:
                detail += (
                    f"Suspicious phrases detected include: "
                    f"'{triggered[0]}'"
                    + (f", '{triggered[1]}'" if len(triggered) > 1 else "")
                    + ". "
                )
            detail += (
                "Phishing pages typically create artificial urgency to pressure users "
                "into acting before they can evaluate the legitimacy of the request."
            )
            cards.append({
                "severity": "high",
                "icon": "🧠",
                "title": "NLP model: high phishing language confidence",
                "detail": detail,
            })

        elif nlp_prob >= MEDIUM_THRESHOLD:
            cards.append({
                "severity": "medium",
                "icon": "💬",
                "title": "Suspicious urgency language detected",
                "detail": (
                    f"The page content contains language patterns associated with phishing "
                    f"(NLP confidence: {nlp_prob:.0%}). "
                    "Common patterns include requests to verify credentials, account suspension "
                    "warnings, or time-limited offers designed to bypass rational evaluation."
                ),
            })

        return cards

    # ─────────────────────────────────────────────────────────────────────
    # CNN-based explanations
    # ─────────────────────────────────────────────────────────────────────
    def _explain_cnn(self, cnn_prob: float) -> list[dict]:
        if cnn_prob < MEDIUM_THRESHOLD:
            return []

        sev = _severity(cnn_prob)

        if sev == "high":
            return [{
                "severity": "high",
                "icon": "👁️",
                "title": "Visual brand impersonation detected",
                "detail": (
                    f"The MobileNetV2 visual model identified this page as closely resembling "
                    f"a known brand's login or landing page (confidence: {cnn_prob:.0%}). "
                    "Visual clone attacks replicate the exact layout, colour scheme, logo, and "
                    "typography of trusted sites to deceive users into entering credentials."
                ),
            }]
        else:
            return [{
                "severity": "medium",
                "icon": "🖼️",
                "title": "Possible visual similarity to known brand",
                "detail": (
                    f"The page layout shows moderate visual similarity to known brand pages "
                    f"(CNN confidence: {cnn_prob:.0%}). "
                    "This may indicate a partial clone or a brand-inspired design intended to "
                    "create a false sense of familiarity."
                ),
            }]

    # ─────────────────────────────────────────────────────────────────────
    # WHOIS domain age explanations
    # ─────────────────────────────────────────────────────────────────────
    def _explain_whois(self, whois_age_days: Optional[int]) -> list[dict]:
        if whois_age_days is None:
            return [{
                "severity": "medium",
                "icon": "🔍",
                "title": "Domain registration date unavailable",
                "detail": (
                    "WHOIS data for this domain could not be retrieved. "
                    "Legitimate organisations typically have verifiable registration records. "
                    "Absence of WHOIS data may indicate a privacy-protected or recently "
                    "registered domain used specifically for this attack."
                ),
            }]

        if whois_age_days < 7:
            return [{
                "severity": "high",
                "icon": "🗓️",
                "title": f"Domain registered {whois_age_days} day(s) ago",
                "detail": (
                    f"This domain was registered only {whois_age_days} day(s) ago. "
                    "Phishing campaigns routinely register domains hours before launching an "
                    "attack to evade reputation-based blacklists. A domain this new has "
                    "virtually no established trust history."
                ),
            }]

        if whois_age_days < 30:
            return [{
                "severity": "high",
                "icon": "🗓️",
                "title": f"Very new domain: registered {whois_age_days} days ago",
                "detail": (
                    f"This domain was registered {whois_age_days} days ago. "
                    "Legitimate financial and e-commerce platforms are established organisations "
                    "with years of registration history. A 30-day-old domain impersonating a "
                    "major brand is a strong phishing indicator."
                ),
            }]

        if whois_age_days < 90:
            return [{
                "severity": "medium",
                "icon": "🗓️",
                "title": f"Recently registered domain ({whois_age_days} days old)",
                "detail": (
                    f"This domain was registered {whois_age_days} days ago. "
                    "While not conclusive on its own, a relatively new domain combined with "
                    "other threat signals warrants caution."
                ),
            }]

        return []   # Old domain = no explanation card needed

    # ─────────────────────────────────────────────────────────────────────
    # SSL/TLS explanations
    # ─────────────────────────────────────────────────────────────────────
    def _explain_ssl(self, url: str, features: dict) -> list[dict]:
        cards = []

        if not url.startswith("https://"):
            cards.append({
                "severity": "high",
                "icon": "🔓",
                "title": "No HTTPS — connection is unencrypted",
                "detail": (
                    "This page does not use HTTPS. All legitimate credential forms (login, "
                    "payment, account registration) must use HTTPS to encrypt data in transit. "
                    "Submitting credentials over HTTP exposes them to interception."
                ),
            })

        # Self-signed or free DV cert combined with high overall risk
        ssl_risk = features.get("ssl_risk", 0.0)
        if ssl_risk >= HIGH_THRESHOLD and url.startswith("https://"):
            cards.append({
                "severity": "medium",
                "icon": "🔒",
                "title": "SSL certificate risk indicators detected",
                "detail": (
                    "The site uses HTTPS but exhibits SSL certificate risk patterns. "
                    "Phishing sites increasingly use free Let's Encrypt certificates "
                    "to display the padlock icon while still being fraudulent. "
                    "HTTPS alone does not guarantee a site is legitimate."
                ),
            })

        return cards
