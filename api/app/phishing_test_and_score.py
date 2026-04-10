"""
phishing_scoring_engine.py

A reusable phishing scoring engine based on a 1000-point model.

Purpose:
    - Score URLs/webpages using a weighted phishing-indicator model
    - Support both built-in URL heuristics and externally supplied analysis results
    - Return a structured result that can be used by a CLI, web app, API, or local tool

Design Notes:
    - Some phishing indicators can be derived directly from the URL
    - Other indicators require outside data sources or deeper content analysis
      (WHOIS, DNS, SSL, page scraping, VirusTotal, phishing database checks, etc.)
    - Those external results are passed into the scoring engine through an
      "analysis_context" dictionary

Usage Example:
    engine = PhishingScoringEngine()
    result = engine.score_url(
        url="http://paypal.com@evil-login.xyz/secure",
        displayed_url="https://paypal.com",
        analysis_context={
            "found_in_known_phishing_database": True,
            "domain_age_days": 5,
            "domain_reputation_malicious": True,
            "ssl_certificate_mismatch": True,
            "external_form_submission": True,
            "credential_harvesting_language": True,
            "brand_impersonation": True,
            "login_form_present": True,
            "urgent_threatening_language": True,
            "multiple_redirects_detected": True,
        }
    )
    print(result)

Author:
    OpenAI / ChatGPT

"""

from __future__ import annotations

import re
import ipaddress
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse, unquote


# ---------------------------------------------------------------------------
# DATA CLASSES
# ---------------------------------------------------------------------------

@dataclass
class TriggeredIndicator:
    """
    Represents one indicator that was triggered during scoring.
    """
    name: str
    score: int
    severity: str
    explanation: str


@dataclass
class PhishingScoreResult:
    """
    Final structured result returned by the scoring engine.
    """
    url: str
    normalized_url: str
    domain: str
    raw_score: int
    final_score: int
    risk_level: str
    triggered_indicators: List[TriggeredIndicator]
    notes: List[str]

    def to_dict(self) -> Dict[str, Any]:
        """
        Convert the result to a dictionary that is easy to serialize to JSON.
        """
        return {
            "url": self.url,
            "normalized_url": self.normalized_url,
            "domain": self.domain,
            "raw_score": self.raw_score,
            "final_score": self.final_score,
            "risk_level": self.risk_level,
            "triggered_indicators": [asdict(ind) for ind in self.triggered_indicators],
            "notes": self.notes,
        }


# ---------------------------------------------------------------------------
# PHISHING SCORING ENGINE
# ---------------------------------------------------------------------------

class PhishingScoringEngine:
    """
    Main phishing scoring engine.

    This class implements the 36-indicator model discussed previously.
    It combines:
        1. URL-only heuristics
        2. externally supplied intelligence / analysis
        3. final risk bucketing

    Important:
        Not every phishing indicator can be detected from the URL alone.
        For example:
            - domain age
            - WHOIS privacy
            - SSL mismatch
            - login form presence
            - hidden iframe
            - phishing database match
            - VirusTotal or external reputation

        Those should be passed into the `analysis_context` parameter.
    """

    # -----------------------------------------------------------------------
    # CENTRAL INDICATOR TABLE
    # -----------------------------------------------------------------------
    #
    # This is your master scoring model.
    # Each indicator has:
    #   - score
    #   - severity
    #   - explanation
    #
    # The keys in this dictionary are used internally by the engine.
    # -----------------------------------------------------------------------

    INDICATORS: Dict[str, Dict[str, Any]] = {
        "found_in_known_phishing_database": {
            "score": 400,
            "severity": "Critical",
            "explanation": "URL was found in a known phishing database."
        },
        "ip_address_in_url": {
            "score": 100,
            "severity": "High",
            "explanation": "The URL uses a raw IP address instead of a normal domain."
        },
        "at_symbol_in_url": {
            "score": 100,
            "severity": "High",
            "explanation": "The URL contains an @ symbol, which can be used to mislead users."
        },
        "domain_age_under_30_days": {
            "score": 90,
            "severity": "High",
            "explanation": "The domain appears to be newly registered."
        },
        "domain_reputation_malicious": {
            "score": 100,
            "severity": "High",
            "explanation": "The domain has a malicious or poor reputation."
        },
        "ssl_certificate_mismatch": {
            "score": 90,
            "severity": "High",
            "explanation": "The SSL/TLS certificate does not match the domain."
        },
        "external_form_submission": {
            "score": 100,
            "severity": "High",
            "explanation": "A form submits data to a different external domain."
        },
        "credential_harvesting_language": {
            "score": 90,
            "severity": "High",
            "explanation": "The page contains language commonly used to steal credentials."
        },
        "brand_impersonation": {
            "score": 90,
            "severity": "High",
            "explanation": "The page appears to impersonate a trusted brand."
        },
        "url_shortener_used": {
            "score": 80,
            "severity": "High",
            "explanation": "A URL shortener is being used to hide the true destination."
        },
        "typosquatting_domain": {
            "score": 100,
            "severity": "High",
            "explanation": "The domain closely resembles a legitimate one but appears misspelled."
        },
        "excessive_subdomains": {
            "score": 60,
            "severity": "Medium",
            "explanation": "The domain contains an unusually high number of subdomains."
        },
        "suspicious_tld": {
            "score": 60,
            "severity": "Medium",
            "explanation": "The domain uses a top-level domain frequently abused by phishing sites."
        },
        "whois_privacy_enabled": {
            "score": 40,
            "severity": "Medium",
            "explanation": "WHOIS privacy is enabled, hiding domain ownership."
        },
        "recently_issued_ssl_certificate": {
            "score": 50,
            "severity": "Medium",
            "explanation": "The SSL certificate was issued very recently."
        },
        "long_url": {
            "score": 50,
            "severity": "Medium",
            "explanation": "The URL is unusually long, which can be used to hide malicious intent."
        },
        "multiple_hyphens_in_domain": {
            "score": 50,
            "severity": "Medium",
            "explanation": "The domain contains multiple hyphens, a common phishing pattern."
        },
        "encoded_obfuscated_url": {
            "score": 60,
            "severity": "Medium",
            "explanation": "The URL contains encoded or obfuscated characters."
        },
        "multiple_redirects_detected": {
            "score": 60,
            "severity": "Medium",
            "explanation": "The site performed multiple redirects."
        },
        "javascript_obfuscation": {
            "score": 70,
            "severity": "Medium",
            "explanation": "The page contains obfuscated JavaScript."
        },
        "hidden_iframe": {
            "score": 70,
            "severity": "Medium",
            "explanation": "The page contains a hidden iframe."
        },
        "external_resource_loading": {
            "score": 50,
            "severity": "Medium",
            "explanation": "The page loads external resources from suspicious third-party sources."
        },
        "login_form_present": {
            "score": 20,
            "severity": "Low",
            "explanation": "The page contains a login form."
        },
        "urgent_threatening_language": {
            "score": 30,
            "severity": "Low",
            "explanation": "The page uses urgent or threatening language to pressure the user."
        },
        "financial_request_language": {
            "score": 30,
            "severity": "Low",
            "explanation": "The page requests financial or payment-related information."
        },
        "unexpected_login_prompt": {
            "score": 20,
            "severity": "Low",
            "explanation": "The page unexpectedly asks the user to log in."
        },
        "fake_login_path": {
            "score": 30,
            "severity": "Low",
            "explanation": "The path appears to mimic a legitimate login or security portal."
        },
        "excessive_dots_in_url": {
            "score": 20,
            "severity": "Low",
            "explanation": "The URL contains an unusual number of dot separators."
        },
        "homoglyph_attack": {
            "score": 30,
            "severity": "Low",
            "explanation": "The domain may contain lookalike characters intended to deceive users."
        },
        "missing_abnormal_dns_records": {
            "score": 30,
            "severity": "Low",
            "explanation": "DNS records appear missing or abnormal."
        },
        "url_display_mismatch": {
            "score": 30,
            "severity": "Low",
            "explanation": "The displayed URL differs from the actual destination URL."
        },
        "excessive_permission_requests": {
            "score": 60,
            "severity": "Medium",
            "explanation": "The page requests excessive browser permissions."
        },
        "random_algorithmic_domain_string": {
            "score": 70,
            "severity": "Medium",
            "explanation": "The domain contains a random or algorithmically generated-looking string."
        },
        "favicon_loaded_from_external_domain": {
            "score": 40,
            "severity": "Medium",
            "explanation": "The favicon is loaded from an unrelated external domain."
        },
        "no_contact_or_privacy_policy": {
            "score": 30,
            "severity": "Low",
            "explanation": "The site lacks typical business legitimacy signals like contact or privacy info."
        },
        "inconsistent_branding_or_design": {
            "score": 30,
            "severity": "Low",
            "explanation": "The page has inconsistent branding, poor design, or mismatched visuals."
        },
    }

    # Common URL shortener domains
    SHORTENER_DOMAINS = {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "buff.ly",
        "is.gd", "rebrand.ly", "shorturl.at", "cutt.ly", "rb.gy", "soo.gd"
    }

    # TLDs frequently seen in abuse cases.
    # This list is not absolute truth; it is a heuristic.
    SUSPICIOUS_TLDS = {
        "xyz", "top", "tk", "gq", "work", "click", "country", "stream",
        "download", "xin", "men", "review", "party", "zip", "mov", "ru"
    }

    # Common words often seen in fake login/security-related paths
    SUSPICIOUS_PATH_KEYWORDS = {
        "login", "signin", "verify", "secure", "update", "account",
        "confirm", "password", "auth", "unlock", "billing", "validate"
    }

    # -----------------------------------------------------------------------
    # PUBLIC API
    # -----------------------------------------------------------------------

    def score_url(
        self,
        url: str,
        displayed_url: Optional[str] = None,
        analysis_context: Optional[Dict[str, Any]] = None
    ) -> PhishingScoreResult:
        """
        Score a URL and return a structured phishing result.

        Parameters:
            url:
                The actual URL to score.

            displayed_url:
                Optional user-visible link text / displayed URL. Useful for
                detecting "URL display mismatch" if the displayed link differs
                from the actual underlying URL.

            analysis_context:
                Optional dictionary of additional analysis inputs.
                This is where you pass in results from:
                    - phishing database check
                    - VirusTotal
                    - WHOIS lookup
                    - DNS inspection
                    - SSL inspection
                    - HTML/content parsing
                    - redirect tracing
                    - page behavior analysis

                Example:
                    {
                        "found_in_known_phishing_database": True,
                        "domain_age_days": 12,
                        "domain_reputation_malicious": True,
                        "ssl_certificate_mismatch": True,
                        "external_form_submission": True
                    }

        Returns:
            PhishingScoreResult
        """
        analysis_context = analysis_context or {}

        normalized_url = self._normalize_url(url)
        parsed = urlparse(normalized_url)
        domain = parsed.netloc.lower()

        triggered: List[TriggeredIndicator] = []
        notes: List[str] = []

        # ---------------------------------------------------------------
        # 1. Built-in URL-based heuristic checks
        # ---------------------------------------------------------------
        builtin_flags = self._run_builtin_url_checks(
            normalized_url=normalized_url,
            displayed_url=displayed_url
        )

        # ---------------------------------------------------------------
        # 2. Convert external analysis_context values into indicator flags
        # ---------------------------------------------------------------
        external_flags = self._run_external_context_checks(
            domain=domain,
            analysis_context=analysis_context,
            notes=notes
        )

        # Merge flags.
        # If either source says True, the indicator is considered triggered.
        all_flags = {**builtin_flags, **external_flags}
        for key, value in builtin_flags.items():
            if value:
                all_flags[key] = True
        for key, value in external_flags.items():
            if value:
                all_flags[key] = True

        # ---------------------------------------------------------------
        # 3. Build triggered indicator list and sum the raw score
        # ---------------------------------------------------------------
        raw_score = 0

        for indicator_name, is_triggered in all_flags.items():
            if not is_triggered:
                continue

            indicator_meta = self.INDICATORS.get(indicator_name)
            if not indicator_meta:
                # If an indicator name is unknown, skip it safely.
                notes.append(f"Unknown indicator '{indicator_name}' was ignored.")
                continue

            raw_score += indicator_meta["score"]
            triggered.append(
                TriggeredIndicator(
                    name=indicator_name,
                    score=indicator_meta["score"],
                    severity=indicator_meta["severity"],
                    explanation=indicator_meta["explanation"]
                )
            )

        # ---------------------------------------------------------------
        # 4. Apply intelligent score shaping rules
        # ---------------------------------------------------------------
        #
        # These rules help make the final result more realistic.
        # They are optional but useful.
        # ---------------------------------------------------------------

        adjusted_score = self._apply_scoring_rules(
            raw_score=raw_score,
            flags=all_flags,
            analysis_context=analysis_context,
            notes=notes
        )

        # Cap at 1000 as discussed in your model.
        final_score = min(adjusted_score, 1000)

        # ---------------------------------------------------------------
        # 5. Convert score into risk bucket
        # ---------------------------------------------------------------
        risk_level = self._determine_risk_level(final_score)

        return PhishingScoreResult(
            url=url,
            normalized_url=normalized_url,
            domain=domain,
            raw_score=raw_score,
            final_score=final_score,
            risk_level=risk_level,
            triggered_indicators=sorted(triggered, key=lambda x: x.score, reverse=True),
            notes=notes
        )

    # -----------------------------------------------------------------------
    # BUILT-IN URL CHECKS
    # -----------------------------------------------------------------------

    def _run_builtin_url_checks(
        self,
        normalized_url: str,
        displayed_url: Optional[str]
    ) -> Dict[str, bool]:
        """
        Run checks that can be derived directly from the URL itself.

        These are "offline" heuristics and do not require network access.
        """
        flags = {key: False for key in self.INDICATORS.keys()}

        parsed = urlparse(normalized_url)
        domain = parsed.netloc.lower()
        path = parsed.path.lower()
        full_lower = normalized_url.lower()

        # IP address in URL
        if self._is_ip_address(domain):
            flags["ip_address_in_url"] = True

        # @ symbol in URL
        if "@" in normalized_url:
            flags["at_symbol_in_url"] = True

        # URL shortener
        if domain in self.SHORTENER_DOMAINS:
            flags["url_shortener_used"] = True

        # Long URL
        if len(normalized_url) > 75:
            flags["long_url"] = True

        # Multiple hyphens in domain
        if domain.count("-") >= 2:
            flags["multiple_hyphens_in_domain"] = True

        # Excessive subdomains
        subdomain_count = self._count_subdomains(domain)
        if subdomain_count > 3:
            flags["excessive_subdomains"] = True

        # Suspicious TLD
        tld = self._extract_tld(domain)
        if tld in self.SUSPICIOUS_TLDS:
            flags["suspicious_tld"] = True

        # Encoded or obfuscated URL
        if self._has_encoded_characters(normalized_url):
            flags["encoded_obfuscated_url"] = True

        # Excessive dots in URL
        if normalized_url.count(".") > 4:
            flags["excessive_dots_in_url"] = True

        # Fake login path
        if any(keyword in path for keyword in self.SUSPICIOUS_PATH_KEYWORDS):
            flags["fake_login_path"] = True

        # Homoglyph-style suspicion
        if self._looks_like_homoglyph_attack(domain):
            flags["homoglyph_attack"] = True

        # Random / algorithmic domain string
        if self._looks_algorithmic(domain):
            flags["random_algorithmic_domain_string"] = True

        # Displayed URL mismatch
        if displayed_url:
            displayed_normalized = self._normalize_url(displayed_url)
            if displayed_normalized != normalized_url:
                flags["url_display_mismatch"] = True

        return flags

    # -----------------------------------------------------------------------
    # EXTERNAL CONTEXT CHECKS
    # -----------------------------------------------------------------------

    def _run_external_context_checks(
        self,
        domain: str,
        analysis_context: Dict[str, Any],
        notes: List[str]
    ) -> Dict[str, bool]:
        """
        Convert externally supplied analysis results into indicator flags.

        Example analysis_context keys supported by this engine:
            found_in_known_phishing_database: bool
            domain_age_days: int
            domain_reputation_malicious: bool
            ssl_certificate_mismatch: bool
            external_form_submission: bool
            credential_harvesting_language: bool
            brand_impersonation: bool
            typosquatting_domain: bool
            whois_privacy_enabled: bool
            recently_issued_ssl_certificate: bool
            multiple_redirects_detected: bool
            javascript_obfuscation: bool
            hidden_iframe: bool
            external_resource_loading: bool
            login_form_present: bool
            urgent_threatening_language: bool
            financial_request_language: bool
            unexpected_login_prompt: bool
            missing_abnormal_dns_records: bool
            excessive_permission_requests: bool
            favicon_loaded_from_external_domain: bool
            no_contact_or_privacy_policy: bool
            inconsistent_branding_or_design: bool
        """
        flags = {key: False for key in self.INDICATORS.keys()}

        # Direct boolean mappings
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
            if analysis_context.get(key) is True:
                flags[key] = True

        # Domain age handling
        domain_age_days = analysis_context.get("domain_age_days")
        if isinstance(domain_age_days, int):
            if domain_age_days < 30:
                flags["domain_age_under_30_days"] = True
        elif domain_age_days is not None:
            notes.append("domain_age_days was provided but was not an integer.")

        return flags

    # -----------------------------------------------------------------------
    # SCORING RULES
    # -----------------------------------------------------------------------

    def _apply_scoring_rules(
        self,
        raw_score: int,
        flags: Dict[str, bool],
        analysis_context: Dict[str, Any],
        notes: List[str]
    ) -> int:
        """
        Apply scoring adjustments / shaping rules.

        Why this exists:
            The raw score alone is useful, but some combinations deserve
            stronger interpretation. For example:
                - database match
                - strong phishing combinations
                - known malicious reputation
                - external form + brand impersonation + credential prompts

        Current rules:
            1. Known phishing database match:
                force minimum score of 900
            2. Strong phishing combo:
                brand impersonation + credential harvesting + external form
                add +100
            3. Login lure combo:
                login form + urgent language + unexpected login prompt
                add +50
            4. Malicious reputation + domain age under 30:
                add +50
            5. Safe reputation override:
                if caller explicitly passes signals that the site is well-established
                and reputable, dampen very low-confidence cases

        You can modify these rules to match your project needs.
        """
        adjusted = raw_score

        # Rule 1: known phishing database match is extremely strong evidence
        if flags.get("found_in_known_phishing_database"):
            adjusted = max(adjusted, 900)
            notes.append("Known phishing database match triggered minimum score of 900.")

        # Rule 2: powerful credential theft combo
        if (
            flags.get("brand_impersonation")
            and flags.get("credential_harvesting_language")
            and flags.get("external_form_submission")
        ):
            adjusted += 100
            notes.append("Added +100 for brand impersonation + credential harvesting + external form combo.")

        # Rule 3: strong login pressure combo
        if (
            flags.get("login_form_present")
            and flags.get("urgent_threatening_language")
            and flags.get("unexpected_login_prompt")
        ):
            adjusted += 50
            notes.append("Added +50 for pressured login combo.")

        # Rule 4: newly registered + malicious reputation
        if (
            flags.get("domain_age_under_30_days")
            and flags.get("domain_reputation_malicious")
        ):
            adjusted += 50
            notes.append("Added +50 for malicious reputation on a newly registered domain.")

        # Rule 5: optional safe override support
        #
        # This does not erase genuinely suspicious results. It only helps keep
        # obviously low-risk sites from looking worse than they should when a few
        # weak heuristics trigger.
        #
        # Supported external flags:
        #   analysis_context["domain_age_days"] > 365
        #   analysis_context["domain_reputation_good"] == True
        #   analysis_context["ssl_certificate_valid"] == True
        #
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
            notes.append("Applied safe override for mature domain with good reputation and valid SSL.")

        return adjusted

    # -----------------------------------------------------------------------
    # RISK LEVEL DETERMINATION
    # -----------------------------------------------------------------------

    def _determine_risk_level(self, final_score: int) -> str:
        """
        Convert numeric score to a friendly risk bucket.
        """
        if 0 <= final_score <= 200:
            return "Legitimate / Low Risk"
        if 201 <= final_score <= 400:
            return "Suspicious"
        if 401 <= final_score <= 600:
            return "Likely Phishing"
        return "High Confidence Phishing"

    # -----------------------------------------------------------------------
    # HELPER METHODS
    # -----------------------------------------------------------------------

    def _normalize_url(self, url: str) -> str:
        """
        Normalize a URL enough for basic comparison and scoring.

        This is intentionally simple:
            - trims whitespace
            - adds http:// if no scheme is present
        """
        url = url.strip()
        if not re.match(r"^[a-zA-Z][a-zA-Z0-9+\-.]*://", url):
            url = "http://" + url
        return url

    def _is_ip_address(self, domain: str) -> bool:
        """
        Return True if the domain/netloc appears to be a raw IP address.
        """
        # Remove port if present
        host = domain.split(":")[0]
        try:
            ipaddress.ip_address(host)
            return True
        except ValueError:
            return False

    def _count_subdomains(self, domain: str) -> int:
        """
        Roughly count subdomains.

        Example:
            login.secure.paypal.example.com
            base domain guess: example.com
            subdomains: login.secure.paypal -> count = 3

        This is heuristic-based and not a full public suffix parser.
        """
        host = domain.split(":")[0]
        parts = [p for p in host.split(".") if p]

        # Need at least domain + TLD to have subdomains
        if len(parts) <= 2:
            return 0

        return len(parts) - 2

    def _extract_tld(self, domain: str) -> str:
        """
        Extract the last label of the domain as the TLD.
        """
        host = domain.split(":")[0]
        parts = [p for p in host.split(".") if p]
        return parts[-1].lower() if parts else ""

    def _has_encoded_characters(self, url: str) -> bool:
        """
        Detect signs of URL encoding or obfuscation.

        We treat:
            - percent-encoding (%2F, %40, etc.)
            - URL that changes significantly when decoded
        as suspicious indicators.
        """
        if "%" in url:
            return True

        decoded = unquote(url)
        return decoded != url

    def _looks_like_homoglyph_attack(self, domain: str) -> bool:
        """
        Very simple heuristic for common lookalike patterns.

        This does NOT fully solve homoglyph detection.
        It only catches some obvious patterns such as:
            - rnicrosoft (rn vs m)
            - paypa1 (1 vs l)
            - micr0soft (0 vs o)
            - gooqle (q vs g style mistakes)

        A production system would use a more advanced confusable-character library.
        """
        suspicious_patterns = [
            "rn",   # rn replacing m in some contexts
            "0",    # zero replacing o
            "1",    # one replacing l or i
            "vv",   # vv replacing w
        ]

        # We do not want this to trigger on every normal domain.
        # Only mark it when the domain also appears brand-like or unusual.
        domain_without_dots = domain.replace(".", "")

        if any(pattern in domain_without_dots for pattern in suspicious_patterns):
            # Add a little control so normal cases do not over-trigger:
            if len(re.findall(r"[0-9]", domain_without_dots)) > 0 or "rn" in domain_without_dots:
                return True

        return False

    def _looks_algorithmic(self, domain: str) -> bool:
        """
        Heuristic for random / algorithmic-looking domain strings.

        This tries to catch domains that look machine-generated, for example:
            xj39sk-login-update.com

        Simple indicators:
            - long alphanumeric runs
            - too many digits
            - strange consonant-heavy chunks
        """
        host = domain.split(":")[0]
        host_no_tld = host.split(".")[0]

        # Count digits
        digit_count = sum(ch.isdigit() for ch in host_no_tld)

        # Long mixed alphanumeric chunk
        if re.search(r"[a-z]{2,}\d{2,}[a-z0-9]{2,}", host_no_tld):
            return True

        # Heavy digit density
        if len(host_no_tld) >= 10 and digit_count >= 3:
            return True

        # Strange consonant-heavy pattern
        consonant_clusters = re.findall(r"[bcdfghjklmnpqrstvwxyz]{5,}", host_no_tld, re.IGNORECASE)
        if consonant_clusters:
            return True

        return False


# ---------------------------------------------------------------------------
# EXAMPLE USAGE
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    """
    Demonstration block.

    This section lets you run the file directly for quick testing.
    In a larger project, you would usually import PhishingScoringEngine
    into another file and call it from there.
    """

    engine = PhishingScoringEngine()

    sample_url = "http://paypal.com@evil-login.xyz/secure-login"

    # Example external analysis results.
    # In a real project, these might come from:
    #   - VirusTotal
    #   - PhishTank / URLhaus
    #   - WHOIS lookup
    #   - SSL inspection
    #   - HTML parser / browser automation
    sample_context = {
        "found_in_known_phishing_database": True,
        "domain_age_days": 8,
        "domain_reputation_malicious": True,
        "ssl_certificate_mismatch": True,
        "external_form_submission": True,
        "credential_harvesting_language": True,
        "brand_impersonation": True,
        "multiple_redirects_detected": True,
        "login_form_present": True,
        "urgent_threatening_language": True,
        "unexpected_login_prompt": True,
        "javascript_obfuscation": False,
        "hidden_iframe": False,
        "external_resource_loading": True,
        "whois_privacy_enabled": True,
    }

    result = engine.score_url(
        url=sample_url,
        displayed_url="https://paypal.com",
        analysis_context=sample_context
    )

    print("\n=== PHISHING SCORING RESULT ===")
    print(f"URL: {result.url}")
    print(f"Normalized URL: {result.normalized_url}")
    print(f"Domain: {result.domain}")
    print(f"Raw Score: {result.raw_score}")
    print(f"Final Score: {result.final_score}")
    print(f"Risk Level: {result.risk_level}")

    print("\nTriggered Indicators:")
    for indicator in result.triggered_indicators:
        print(
            f"- {indicator.name} | +{indicator.score} | "
            f"{indicator.severity} | {indicator.explanation}"
        )

    if result.notes:
        print("\nNotes:")
        for note in result.notes:
            print(f"- {note}")