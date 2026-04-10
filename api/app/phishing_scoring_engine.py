"""
phishing_scoring_engine.py

Purpose:
    Central phishing scoring engine that main.py can call after the helper
    modules have gathered enrichment data.

Main callable usage:
    from phishing_scoring_engine import PhishingScoringEngine

    engine = PhishingScoringEngine()
    result = engine.score_url(url, displayed_url=None, analysis_context={...})

Design:
    - URL-only indicators are computed inside this file.
    - Enrichment-based indicators are passed in via analysis_context.
    - The result object includes a .to_dict() helper for easy JSON responses.
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
    """Weighted phishing indicator engine."""

    INDICATORS: Dict[str, Dict[str, Any]] = {
        "found_in_known_phishing_database": {"score": 400, "severity": "Critical", "explanation": "URL found in known phishing database."},
        "ip_address_in_url": {"score": 100, "severity": "High", "explanation": "Raw IP used instead of a normal domain."},
        "at_symbol_in_url": {"score": 100, "severity": "High", "explanation": "URL contains @ symbol, which can hide the real destination."},
        "domain_age_under_30_days": {"score": 90, "severity": "High", "explanation": "Domain is newly registered."},
        "domain_reputation_malicious": {"score": 100, "severity": "High", "explanation": "Domain reputation is malicious or poor."},
        "ssl_certificate_mismatch": {"score": 90, "severity": "High", "explanation": "Certificate does not match the host/domain."},
        "external_form_submission": {"score": 100, "severity": "High", "explanation": "Form submits to a different external domain."},
        "credential_harvesting_language": {"score": 90, "severity": "High", "explanation": "Page contains credential theft language."},
        "brand_impersonation": {"score": 90, "severity": "High", "explanation": "Trusted brand appears to be impersonated."},
        "url_shortener_used": {"score": 80, "severity": "High", "explanation": "URL shortener hides real destination."},
        "typosquatting_domain": {"score": 100, "severity": "High", "explanation": "Domain appears to imitate a legitimate domain with a slight misspelling."},
        "excessive_subdomains": {"score": 60, "severity": "Medium", "explanation": "Too many subdomains present."},
        "suspicious_tld": {"score": 60, "severity": "Medium", "explanation": "TLD commonly abused in phishing."},
        "whois_privacy_enabled": {"score": 40, "severity": "Medium", "explanation": "WHOIS privacy enabled."},
        "recently_issued_ssl_certificate": {"score": 50, "severity": "Medium", "explanation": "SSL certificate issued recently."},
        "long_url": {"score": 50, "severity": "Medium", "explanation": "URL is unusually long."},
        "multiple_hyphens_in_domain": {"score": 50, "severity": "Medium", "explanation": "Domain has multiple hyphens."},
        "encoded_obfuscated_url": {"score": 60, "severity": "Medium", "explanation": "URL contains encoding/obfuscation."},
        "multiple_redirects_detected": {"score": 60, "severity": "Medium", "explanation": "Multiple redirects detected."},
        "javascript_obfuscation": {"score": 70, "severity": "Medium", "explanation": "JavaScript appears obfuscated."},
        "hidden_iframe": {"score": 70, "severity": "Medium", "explanation": "Hidden iframe detected."},
        "external_resource_loading": {"score": 50, "severity": "Medium", "explanation": "External resources loaded from other domains."},
        "login_form_present": {"score": 20, "severity": "Low", "explanation": "Login form present."},
        "urgent_threatening_language": {"score": 30, "severity": "Low", "explanation": "Urgent/threatening language detected."},
        "financial_request_language": {"score": 30, "severity": "Low", "explanation": "Financial request language detected."},
        "unexpected_login_prompt": {"score": 20, "severity": "Low", "explanation": "Unexpected login prompt detected."},
        "fake_login_path": {"score": 30, "severity": "Low", "explanation": "Path resembles a fake login or security path."},
        "excessive_dots_in_url": {"score": 20, "severity": "Low", "explanation": "Excessive dot separators in URL."},
        "homoglyph_attack": {"score": 30, "severity": "Low", "explanation": "Possible homoglyph/lookalike attack."},
        "missing_abnormal_dns_records": {"score": 30, "severity": "Low", "explanation": "Missing or abnormal DNS records."},
        "url_display_mismatch": {"score": 30, "severity": "Low", "explanation": "Displayed URL differs from actual URL."},
        "excessive_permission_requests": {"score": 60, "severity": "Medium", "explanation": "Page requests excessive browser permissions."},
        "random_algorithmic_domain_string": {"score": 70, "severity": "Medium", "explanation": "Domain appears random or algorithmically generated."},
        "favicon_loaded_from_external_domain": {"score": 40, "severity": "Medium", "explanation": "Favicon loaded from a different domain."},
        "no_contact_or_privacy_policy": {"score": 30, "severity": "Low", "explanation": "No contact/privacy policy detected."},
        "inconsistent_branding_or_design": {"score": 30, "severity": "Low", "explanation": "Branding/design appears inconsistent."},
    }

    SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
        "is.gd", "rebrand.ly", "shorturl.at", "cutt.ly", "rb.gy", "soo.gd"
    }

    SUSPICIOUS_TLDS = {
        "xyz", "top", "tk", "gq", "work", "click", "country", "stream",
        "download", "xin", "men", "review", "party", "zip", "mov", "ru"
    }

    SUSPICIOUS_PATH_KEYWORDS = {
        "login", "signin", "verify", "secure", "update", "account",
        "confirm", "password", "auth", "unlock", "billing", "validate"
    }

    def score_url(
        self,
        url: str,
        displayed_url: Optional[str] = None,
        analysis_context: Optional[Dict[str, Any]] = None,
    ) -> PhishingScoreResult:
        """
        Score a URL using built-in URL heuristics plus external context.

        Parameters:
            url:
                The real destination URL.
            displayed_url:
                Optional user-visible URL string for mismatch detection.
            analysis_context:
                A merged dictionary returned by helper modules.
        """
        analysis_context = analysis_context or {}
        notes: List[str] = []

        normalized_url = self._normalize_url(url)
        parsed = urlparse(normalized_url)
        domain = parsed.netloc.lower()

        # Build a full flag map. Everything starts as False and then is turned on
        # by either URL-only checks or enrichment-based checks.
        flags = {key: False for key in self.INDICATORS.keys()}
        flags.update(self._run_builtin_url_checks(normalized_url, displayed_url))
        flags.update(self._run_external_context_checks(analysis_context, notes))

        # Sum the triggered indicators.
        raw_score = 0
        triggered: List[TriggeredIndicator] = []

        for name, is_triggered in flags.items():
            if is_triggered and name in self.INDICATORS:
                meta = self.INDICATORS[name]
                raw_score += meta["score"]
                triggered.append(
                    TriggeredIndicator(
                        name=name,
                        score=meta["score"],
                        severity=meta["severity"],
                        explanation=meta["explanation"],
                    )
                )

        # Apply combo / override logic.
        adjusted_score = self._apply_scoring_rules(raw_score, flags, analysis_context, notes)
        final_score = min(adjusted_score, 1000)
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

    # -----------------------------------------------------------------------
    # BUILT-IN URL-ONLY CHECKS
    # -----------------------------------------------------------------------
    def _run_builtin_url_checks(self, normalized_url: str, displayed_url: Optional[str]) -> Dict[str, bool]:
        flags: Dict[str, bool] = {}

        parsed = urlparse(normalized_url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()

        flags["ip_address_in_url"] = self._is_ip_address(domain)
        flags["at_symbol_in_url"] = "@" in normalized_url
        flags["url_shortener_used"] = domain.split(":")[0] in self.SHORTENER_DOMAINS
        flags["long_url"] = len(normalized_url) > 75
        flags["multiple_hyphens_in_domain"] = domain.count("-") >= 2
        flags["excessive_subdomains"] = self._count_subdomains(domain) > 3
        flags["suspicious_tld"] = self._extract_tld(domain) in self.SUSPICIOUS_TLDS
        flags["encoded_obfuscated_url"] = self._has_encoded_characters(normalized_url)
        flags["excessive_dots_in_url"] = normalized_url.count(".") > 4
        flags["fake_login_path"] = any(keyword in path for keyword in self.SUSPICIOUS_PATH_KEYWORDS)
        flags["homoglyph_attack"] = self._looks_like_homoglyph_attack(domain)
        flags["random_algorithmic_domain_string"] = self._looks_algorithmic(domain)

        if displayed_url:
            flags["url_display_mismatch"] = self._normalize_url(displayed_url) != normalized_url
        else:
            flags["url_display_mismatch"] = False

        return flags

    # -----------------------------------------------------------------------
    # EXTERNAL CONTEXT CHECKS
    # -----------------------------------------------------------------------
    def _run_external_context_checks(self, analysis_context: Dict[str, Any], notes: List[str]) -> Dict[str, bool]:
        flags = {key: False for key in self.INDICATORS.keys()}

        # These indicators are expected to arrive directly from helper modules.
        direct_boolean_keys = [
            "found_in_known_phishing_database",
            "domain_reputation_malicious",
            "ssl_certificate_mismatch",
            "external_form_submission",
            "credential_harvesting_language",
            "brand_impersonation",
            "typosquatting_domain",
            "whois_privacy_enabled",
            "recently_issued_ssl_certificate",
            "multiple_redirects_detected",
            "javascript_obfuscation",
            "hidden_iframe",
            "external_resource_loading",
            "login_form_present",
            "urgent_threatening_language",
            "financial_request_language",
            "unexpected_login_prompt",
            "missing_abnormal_dns_records",
            "excessive_permission_requests",
            "favicon_loaded_from_external_domain",
            "no_contact_or_privacy_policy",
            "inconsistent_branding_or_design",
        ]

        for key in direct_boolean_keys:
            flags[key] = bool(analysis_context.get(key, False))

        # Domain age is numeric, so it needs slightly different handling.
        domain_age_days = analysis_context.get("domain_age_days")
        if isinstance(domain_age_days, int):
            flags["domain_age_under_30_days"] = domain_age_days < 30
        elif domain_age_days is not None:
            notes.append("domain_age_days was provided but was not an integer.")

        return flags

    # -----------------------------------------------------------------------
    # SCORE SHAPING / COMBO LOGIC
    # -----------------------------------------------------------------------
    def _apply_scoring_rules(
        self,
        raw_score: int,
        flags: Dict[str, bool],
        analysis_context: Dict[str, Any],
        notes: List[str],
    ) -> int:
        adjusted = raw_score

        # Strongest possible signal: the URL is already in a phishing database.
        if flags.get("found_in_known_phishing_database"):
            adjusted = max(adjusted, 900)
            notes.append("Known phishing database match set minimum score to 900.")

        # Combo: clear credential theft pattern.
        if (
            flags.get("brand_impersonation")
            and flags.get("credential_harvesting_language")
            and flags.get("external_form_submission")
        ):
            adjusted += 100
            notes.append("Added +100 for credential theft combo.")

        # Combo: pressured login pattern.
        if (
            flags.get("login_form_present")
            and flags.get("urgent_threatening_language")
            and flags.get("unexpected_login_prompt")
        ):
            adjusted += 50
            notes.append("Added +50 for pressured login combo.")

        # Combo: young domain with bad reputation.
        if flags.get("domain_age_under_30_days") and flags.get("domain_reputation_malicious"):
            adjusted += 50
            notes.append("Added +50 for new domain plus bad reputation.")

        # Optional safe override for mature domains with good reputation.
        domain_age_days = analysis_context.get("domain_age_days")
        domain_reputation_good = analysis_context.get("domain_reputation_good", False)
        ssl_certificate_valid = analysis_context.get("ssl_certificate_valid", False)

        if (
            isinstance(domain_age_days, int)
            and domain_age_days > 365
            and domain_reputation_good is True
            and ssl_certificate_valid is True
            and adjusted < 200
        ):
            adjusted = min(adjusted, 150)
            notes.append("Applied safe override for mature reputable domain.")

        return adjusted

    # -----------------------------------------------------------------------
    # RISK BUCKETING
    # -----------------------------------------------------------------------
    def _determine_risk_level(self, final_score: int) -> str:
        if final_score <= 200:
            return "Legitimate / Low Risk"
        if final_score <= 400:
            return "Suspicious"
        if final_score <= 600:
            return "Likely Phishing"
        return "High Confidence Phishing"

    # -----------------------------------------------------------------------
    # SMALL URL HELPERS
    # -----------------------------------------------------------------------
    def _normalize_url(self, url: str) -> str:
        url = url.strip()
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

    def _count_subdomains(self, domain: str) -> int:
        host = domain.split(":")[0]
        parts = [p for p in host.split(".") if p]
        return max(0, len(parts) - 2)

    def _extract_tld(self, domain: str) -> str:
        host = domain.split(":")[0]
        parts = [p for p in host.split(".") if p]
        return parts[-1].lower() if parts else ""

    def _has_encoded_characters(self, url: str) -> bool:
        if "%" in url:
            return True
        return unquote(url) != url

    def _looks_like_homoglyph_attack(self, domain: str) -> bool:
        # This is only a simple heuristic. A full homoglyph detector would need
        # a confusable-character mapping library.
        d = domain.replace(".", "")
        if "rn" in d or "0" in d or "1" in d or "vv" in d:
            if any(ch.isdigit() for ch in d) or "rn" in d:
                return True
        return False

    def _looks_algorithmic(self, domain: str) -> bool:
        # Another heuristic-only detector. This looks for machine-generated-like
        # labels, heavy digit density, or long consonant clusters.
        host = domain.split(":")[0].split(".")[0]
        digit_count = sum(ch.isdigit() for ch in host)

        if re.search(r"[a-z]{2,}\d{2,}[a-z0-9]{2,}", host):
            return True
        if len(host) >= 10 and digit_count >= 3:
            return True
        if re.search(r"[bcdfghjklmnpqrstvwxyz]{5,}", host, re.IGNORECASE):
            return True
        return False


# ---------------------------------------------------------------------------
# EASY STANDALONE TESTING
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    engine = PhishingScoringEngine()
    result = engine.score_url(
        url="http://paypal.com@evil-login.xyz/secure-login",
        displayed_url="https://paypal.com",
        analysis_context={
            "found_in_known_phishing_database": True,
            "domain_age_days": 8,
            "domain_reputation_malicious": True,
            "ssl_certificate_mismatch": True,
            "external_form_submission": True,
            "credential_harvesting_language": True,
            "brand_impersonation": True,
            "login_form_present": True,
            "urgent_threatening_language": True,
            "unexpected_login_prompt": True,
        },
    )
    print(result.to_dict())
