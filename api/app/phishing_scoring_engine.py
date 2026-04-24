"""
phishing_scoring_engine.py

Purpose:
    Central phishing scoring engine with integrated database audit improvements.
    Handles domain-level and URL-level matches with priority de-duplication.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, asdict
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse, unquote


# ---------------------------------------------------------------------------
# RESULT DATA STRUCTURES
# ---------------------------------------------------------------------------
@dataclass
class TriggeredIndicator:
    """Represents one indicator that contributed to the score."""
    name: str
    score: int
    severity: str
    explanation: str


@dataclass
class PhishingScoreResult:
    """Structured scoring result returned to the caller."""
    url: str
    normalized_url: str
    domain: str
    raw_score: int
    final_score: int
    risk_level: str
    triggered_indicators: List[TriggeredIndicator]
    notes: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert the result into a JSON-friendly dictionary."""
        return {
            "url": self.url,
            "normalized_url": self.normalized_url,
            "domain": self.domain,
            "raw_score": self.raw_score,
            "final_score": self.final_score,
            "risk_level": self.risk_level,
            "triggered_indicators": [asdict(i) for i in self.triggered_indicators],
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# MAIN ENGINE
# ---------------------------------------------------------------------------
class PhishingScoringEngine:
    """Weighted phishing indicator engine with Database Priority Logic."""

    INDICATORS: Dict[str, Dict[str, Any]] = {
        # --- Audit-Improved Database Indicators ---
        "url_in_phishing_db": {"score": 500, "severity": "Critical", "explanation": "Exact URL found in phishing database."},
        "domain_in_phishing_db": {"score": 400, "severity": "Critical", "explanation": "Domain found in known malicious database."},
        
        # --- High Severity ---
        "ip_address_in_url": {"score": 100, "severity": "High", "explanation": "Raw IP used instead of a normal domain."},
        "at_symbol_in_url": {"score": 100, "severity": "High", "explanation": "URL contains @ symbol."},
        "domain_age_under_30_days": {"score": 90, "severity": "High", "explanation": "Domain is newly registered."},
        "domain_reputation_malicious": {"score": 150, "severity": "High", "explanation": "Domain reputation is malicious or poor."},
        "ssl_certificate_mismatch": {"score": 90, "severity": "High", "explanation": "Certificate does not match host."},
        "external_form_submission": {"score": 100, "severity": "High", "explanation": "Form submits to external domain."},
        "brand_impersonation": {"score": 90, "severity": "High", "explanation": "Trusted brand impersonation detected."},
        "typosquatting_domain": {"score": 100, "severity": "High", "explanation": "Domain imitates a legitimate domain."},

        # --- Medium Severity ---
        "url_shortener_used": {"score": 80, "severity": "High", "explanation": "URL shortener used."},
        "excessive_subdomains": {"score": 60, "severity": "Medium", "explanation": "Too many subdomains present."},
        "suspicious_tld": {"score": 60, "severity": "Medium", "explanation": "TLD commonly abused in phishing."},
        "encoded_obfuscated_url": {"score": 60, "severity": "Medium", "explanation": "URL contains obfuscation."},
        "javascript_obfuscation": {"score": 70, "severity": "Medium", "explanation": "JavaScript appears obfuscated."},
        
        # --- Low Severity ---
        "login_form_present": {"score": 20, "severity": "Low", "explanation": "Login form present."},
        "fake_login_path": {"score": 30, "severity": "Low", "explanation": "Path resembles a login path."},
        "url_display_mismatch": {"score": 30, "severity": "Low", "explanation": "Displayed URL differs from destination."},
    }

    SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "rebrand.ly"}
    SUSPICIOUS_TLDS = {"xyz", "top", "tk", "gq", "zip", "mov", "ru", "click"}
    SUSPICIOUS_PATH_KEYWORDS = {"login", "signin", "verify", "secure", "auth", "billing"}

    def score_url(
        self,
        url: str,
        displayed_url: Optional[str] = None,
        analysis_context: Optional[Dict[str, Any]] = None,
    ) -> PhishingScoreResult:
        analysis_context = analysis_context or {}
        notes: List[str] = []

        normalized_url = self._normalize_url(url)
        parsed = urlparse(normalized_url)
        domain = parsed.netloc.lower()

        # 1. Run checks
        flags = {key: False for key in self.INDICATORS.keys()}
        flags.update(self._run_builtin_url_checks(normalized_url, displayed_url))
        flags.update(self._run_external_context_checks(analysis_context, notes))

        # 2. De-duplication Logic (Audit Improvement)
        # If the exact URL is a match, we don't need to trigger the Domain match separately.
        if flags.get("url_in_phishing_db") and flags.get("domain_in_phishing_db"):
            flags["domain_in_phishing_db"] = False
            notes.append("Superseded domain match with specific URL database match.")

        # 3. Calculate scores
        raw_score = 0
        triggered: List[TriggeredIndicator] = []

        for name, is_triggered in flags.items():
            if is_triggered and name in self.INDICATORS:
                meta = self.INDICATORS[name]
                raw_score += meta["score"]
                triggered.append(TriggeredIndicator(name=name, **meta))

        # 4. Final Shaping and Overrides
        final_score = self._apply_scoring_rules(raw_score, flags, analysis_context, notes)
        final_score = min(final_score, 1000)
        risk_level = self._determine_risk_level(final_score)

        return PhishingScoreResult(
            url=url,
            normalized_url=normalized_url,
            domain=domain,
            raw_score=raw_score,
            final_score=final_score,
            risk_level=risk_level,
            triggered_indicators=sorted(triggered, key=lambda x: x.score, reverse=True),
            notes=notes,
        )

    def _run_builtin_url_checks(self, normalized_url: str, displayed_url: Optional[str]) -> Dict[str, bool]:
        flags: Dict[str, bool] = {}
        parsed = urlparse(normalized_url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        flags["ip_address_in_url"] = self._is_ip_address(domain)
        flags["at_symbol_in_url"] = "@" in normalized_url
        flags["url_shortener_used"] = domain.split(":")[0] in self.SHORTENER_DOMAINS
        flags["suspicious_tld"] = any(domain.endswith(f".{tld}") for tld in self.SUSPICIOUS_TLDS)
        flags["fake_login_path"] = any(keyword in path for keyword in self.SUSPICIOUS_PATH_KEYWORDS)
        
        if displayed_url:
            flags["url_display_mismatch"] = self._normalize_url(displayed_url) != normalized_url
            
        return flags

    def _run_external_context_checks(self, context: Dict[str, Any], notes: List[str]) -> Dict[str, bool]:
        """Handles incoming enrichment data and database results."""
        flags = {key: False for key in self.INDICATORS.keys()}

        # Handle DB Matches (The Hybrid Approach)
        db_matches = context.get("db_matches", [])
        for match in db_matches:
            m_type = match.get("type")
            source = match.get("source", "Unknown Database")
            if m_type == "url":
                flags["url_in_phishing_db"] = True
                notes.append(f"Confirmed URL match in {source}.")
            elif m_type == "domain":
                flags["domain_in_phishing_db"] = True
                notes.append(f"Confirmed domain match in {source}.")

        # Direct boolean mapping for other enrichment
        direct_keys = ["domain_reputation_malicious", "ssl_certificate_mismatch", 
                       "brand_impersonation", "typosquatting_domain"]
        for key in direct_keys:
            flags[key] = bool(context.get(key, False))

        # Domain Age logic
        age = context.get("domain_age_days")
        if isinstance(age, int):
            flags["domain_age_under_30_days"] = age < 30

        return flags

    def _apply_scoring_rules(self, score: int, flags: Dict[str, bool], context: Dict[str, Any], notes: List[str]) -> int:
        # Override: Database matches automatically push score to critical territory
        if flags.get("url_in_phishing_db") or flags.get("domain_in_phishing_db"):
            if score < 900:
                score = 900
                notes.append("Forced score to 900+ due to verified database entry.")
        
        # Safe override for mature, reputable domains
        age = context.get("domain_age_days")
        if isinstance(age, int) and age > 365 and context.get("domain_reputation_good") and score < 300:
            score = min(score, 100)
            notes.append("Applied safe override for mature reputable domain.")
            
        return score

    def _determine_risk_level(self, score: int) -> str:
        if score >= 500: return "High Confidence Phishing"
        if score >= 200: return "Likely Phishing"
        if score >= 60: return "Suspicious"
        return "Legitimate / Low Risk"

    def _normalize_url(self, url: str) -> str:
        url = url.strip().lower()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
            url = "http://" + url
        return url

    def _is_ip_address(self, domain: str) -> bool:
        host = domain.split(":")[0]
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

# ---------------------------------------------------------------------------
# EXAMPLE USAGE
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    engine = PhishingScoringEngine()
    test_context = {
        "db_matches": [
            {"type": "domain", "source": "Google Safe Browsing"},
            {"type": "url", "source": "Internal Blocklist"}
        ],
        "domain_age_days": 5,
        "brand_impersonation": True
    }
    
    result = engine.score_url("http://secure-paypal-login.xyz/update", analysis_context=test_context)
    import json
    print(json.dumps(result.to_dict(), indent=4))