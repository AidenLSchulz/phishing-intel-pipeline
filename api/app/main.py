from __future__ import annotations

import json
import os
import re
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from difflib import SequenceMatcher
from html import unescape
from typing import Dict, List, Optional, Set, Tuple
from urllib import error, parse, request as urllib_request

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --------------------------- Tunable constants ---------------------------- #

SUSPICIOUS_KEYWORDS = {
    "login", "secure", "verify", "account", "update", "bank", "paypal", "signin",
    "wallet", "password", "recovery", "billing", "invoice", "mfa", "auth", "support",
    "helpdesk", "portal", "unlock", "confirm", "sso", "reset", "token", "webscr",
    "microsoft", "amazon", "apple", "google", "office", "outlook",
}

SUSPICIOUS_PHRASES = {
    "verify your account", "confirm your password", "sign in to continue", "update billing",
    "unusual activity", "your account has been limited", "password expires today",
    "session expired", "confirm identity",
}

KNOWN_BRANDS: Dict[str, Set[str]] = {
    "paypal": {"paypal.com"},
    "microsoft": {"microsoft.com", "office.com", "office365.com", "live.com", "outlook.com", "microsoftonline.com"},
    "amazon": {"amazon.com", "amazonaws.com", "amzn.to"},
    "apple": {"apple.com", "icloud.com"},
    "google": {"google.com", "gmail.com", "youtube.com", "googleusercontent.com", "googleapis.com"},
    "facebook": {"facebook.com", "fb.com", "messenger.com"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com"},
    "netflix": {"netflix.com"},
    "adobe": {"adobe.com"},
    "docusign": {"docusign.com"},
    "dropbox": {"dropbox.com", "dropboxusercontent.com.com"},
    "coinbase": {"coinbase.com"},
    "binance": {"binance.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "github": {"github.com", "githubusercontent.com", "github.io"},
}

LEET_TRANSLATION = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
ALT_LEET_TRANSLATION = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "$": "s", "@": "a"})
SUSPICIOUS_TLDS = {"top", "xyz", "click", "shop", "support", "gq", "work", "country", "stream", "buzz", "rest", "fit", "cam", "info"}

KNOWN_PHISHING_FEEDS = [
    "https://openphish.com/feed.txt",
    "https://urlhaus.abuse.ch/downloads/text/",
]
KNOWN_PHISHING_CACHE_FILE = os.path.join(os.path.dirname(__file__), ".known_phishing_cache.json")
KNOWN_PHISHING_CACHE_TTL_SECONDS = 60 * 60 * 6
HTTP_TIMEOUT_SECONDS = 5
SOCKET_TIMEOUT_SECONDS = 5

BUILTIN_KNOWN_PHISHING_DOMAINS = {
    "paypa1-support.com",
    "micr0soft-login.com",
    "amazon-secure-update.net",
}

KNOWN_PHISHING_DOMAINS: Set[str] = set(BUILTIN_KNOWN_PHISHING_DOMAINS)
KNOWN_PHISHING_LAST_REFRESH: Optional[float] = None
KNOWN_PHISHING_LOCK = threading.Lock()


class DomainRequest(BaseModel):
    domain: str


@app.get("/")
def root():
    return {
        "message": "API is running",
        "known_phishing_domains_loaded": len(KNOWN_PHISHING_DOMAINS),
    }


@app.post("/refresh-known-phishing-list")
def refresh_known_phishing_list():
    count = refresh_known_phishing_domains(force=True)
    return {
        "known_phishing_domains_loaded": count,
        "last_refresh": KNOWN_PHISHING_LAST_REFRESH,
    }


@app.post("/analyze-domain")
def analyze_domain(request: DomainRequest):
    original_input = request.domain.strip()
    normalized_domain = normalize_domain(original_input)

    if not normalized_domain:
        return {
            "domain": original_input,
            "normalized_domain": None,
            "risk_score": 0,
            "risk_level": "invalid",
            "risk_label": "Invalid",
            "classification": "invalid",
            "is_legitimate_url": False,
            "is_verified_legitimate": False,
            "reasons": ["Unable to parse a valid domain from input"],
            "signals": {},
            "is_known_phishing": False,
        }

    refresh_known_phishing_domains()

    suspicious_score = 0
    benign_score = 0
    reasons: List[str] = []
    benign_reasons: List[str] = []
    signals: Dict[str, object] = {}

    root_domain = get_registered_domain(normalized_domain)
    signals["registered_domain"] = root_domain

    known_match = is_known_phishing_domain(normalized_domain)
    signals["known_phishing_match"] = known_match
    if known_match:
        suspicious_score += 100
        reasons.append("Domain matches a known phishing domain feed")

    dns_score, dns_benign, dns_reasons, dns_benign_reasons, dns_signals = analyze_dns(normalized_domain)
    suspicious_score += dns_score
    benign_score += dns_benign
    reasons.extend(dns_reasons)
    benign_reasons.extend(dns_benign_reasons)
    signals.update(dns_signals)

    structure_score, structure_reasons, structure_signals = analyze_url_structure(normalized_domain)
    suspicious_score += structure_score
    reasons.extend(structure_reasons)
    signals.update(structure_signals)

    keyword_score, keyword_reasons, matched_keywords = analyze_keywords(normalized_domain)
    suspicious_score += keyword_score
    reasons.extend(keyword_reasons)
    signals["matched_keywords"] = matched_keywords

    brand_score, brand_benign, brand_reasons, brand_benign_reasons, brand_signals = analyze_brand_impersonation(normalized_domain)
    suspicious_score += brand_score
    benign_score += brand_benign
    reasons.extend(brand_reasons)
    benign_reasons.extend(brand_benign_reasons)
    signals.update(brand_signals)

    age_score, age_benign, age_reasons, age_benign_reasons, age_signals = analyze_domain_age(normalized_domain)
    suspicious_score += age_score
    benign_score += age_benign
    reasons.extend(age_reasons)
    benign_reasons.extend(age_benign_reasons)
    signals.update(age_signals)

    tls_score, tls_benign, tls_reasons, tls_benign_reasons, tls_signals = analyze_tls_certificate(normalized_domain)
    suspicious_score += tls_score
    benign_score += tls_benign
    reasons.extend(tls_reasons)
    benign_reasons.extend(tls_benign_reasons)
    signals.update(tls_signals)

    page_score, page_benign, page_reasons, page_benign_reasons, page_signals = analyze_page_content(normalized_domain)
    suspicious_score += page_score
    benign_score += page_benign
    reasons.extend(page_reasons)
    benign_reasons.extend(page_benign_reasons)
    signals.update(page_signals)

    # ------------------------ Compound scoring ---------------------------- #
    compound_boost = 0
    brand_similarity = float(signals.get("brand_similarity", 0) or 0)
    suspected_brand = signals.get("suspected_brand")
    official_brand_domain = bool(signals.get("official_brand_domain"))
    password_field = bool(signals.get("password_field_detected"))
    login_language = bool(signals.get("page_has_login_language"))
    dns_resolves = bool(signals.get("dns_resolves"))
    tls_present = bool(signals.get("tls_present"))
    deceptive_subdomain = bool(signals.get("deceptive_subdomain_keyword"))
    domain_age_days = signals.get("domain_age_days")

    if password_field and suspected_brand and not official_brand_domain:
        compound_boost += 42
        reasons.append("Non-official domain hosts a login form for a known brand")

    if password_field and login_language and suspected_brand and not official_brand_domain:
        compound_boost += 28
        reasons.append("Page combines brand impersonation, login language, and credential harvesting")

    if matched_keywords and brand_similarity >= 0.84 and not official_brand_domain:
        compound_boost += 24
        reasons.append("Domain combines suspicious keywords with brand impersonation")

    if deceptive_subdomain:
        compound_boost += 18
        reasons.append("Subdomain appears to disguise a suspicious login-related keyword")

    if deceptive_subdomain and signals.get("digit_count", 0) >= 1:
        compound_boost += 18
        reasons.append("Subdomain uses digits to disguise a login-related keyword")

    if not dns_resolves and not tls_present and (deceptive_subdomain or brand_similarity >= 0.84 or suspected_brand):
        compound_boost += 25
        reasons.append("Brand-related domain lacks both working DNS and a valid TLS certificate")

    if not official_brand_domain and suspected_brand and not tls_present:
        compound_boost += 20
        reasons.append("Brand-related domain cannot validate a TLS certificate")

    if signals.get("redirected_to_different_host") and suspected_brand and not official_brand_domain:
        compound_boost += 12
        reasons.append("Domain redirects in a way consistent with phishing delivery")

    if isinstance(domain_age_days, int) and domain_age_days <= 30:
        if password_field or brand_similarity >= 0.84 or deceptive_subdomain:
            compound_boost += 22
            reasons.append("Very new domain also shows common phishing behavior")

    if signals.get("page_brand_terms") and matched_keywords and password_field:
        compound_boost += 22
        reasons.append("Page content strongly resembles a credential-harvesting site")

    suspicious_score += compound_boost

    # ------------------------ Final score model -------------------------- #
    if known_match:
        risk_score = 100
    else:
        benign_cap = 0
        if suspicious_score < 20:
            benign_cap = 18
        elif suspicious_score < 35:
            benign_cap = 12
        elif suspicious_score < 60:
            benign_cap = 8
        else:
            benign_cap = 4

        if brand_similarity >= 0.84 or password_field or deceptive_subdomain or suspected_brand:
            benign_cap = min(benign_cap, 5)

        raw_risk_score = suspicious_score - min(benign_score, benign_cap)
        risk_score = max(0, min(raw_risk_score, 100))

    classification, is_legitimate, is_verified_legitimate = classify_domain(
        risk_score=risk_score,
        suspicious_score=suspicious_score,
        benign_score=benign_score,
        known_match=known_match,
        signals=signals,
    )

    # Best UX approach: zero out score only when legitimacy is strongly confirmed.
    if is_verified_legitimate:
        risk_score = 0

    risk_level = risk_score_to_level(risk_score, classification)
    risk_label = classification_to_display_label(classification)

    summary_reasons = unique_preserve_order(reasons)
    if is_legitimate and benign_reasons:
        summary_reasons.extend([f"Legitimacy signal: {item}" for item in unique_preserve_order(benign_reasons)[:5]])
    # 1. Homograph Attack (Punycode)
    # Attackers use 'xn--' to spoof visually similar characters (e.g., apple.com)
    
    if "xn--" in normalized_domain.lower():
        reasons.append("Threat: Homograph/Punycode pattern detected")
    
    sketchy_tlds = [".xyz", "top", ".click", ".support", ".cfd", ".live"]
    if any(normalized_domain.lower().endswith(tld) for tld in sketchy_tlds):
        reasons.append("Threat: Suspicious/High-Risk TLD detected")
    

    protected_brands = ["amazon", "microsoft", "google", "paypal", "apple", "netflix"]
    for brand in protected_brands:
        if brand in normalized_domain.lower() and not normalized_domain.lower().endswith(f"{brand}.com"):
            reasons.append(f"Threat: Unauthorized Brand Impersonation ({brand})")


    if normalized_domain.count('.') >= 3:
        reasons.append("Threat: Excessive subdomain nesting (Potential Proxy)") 
              
    return {
        "domain": original_input,
        "normalized_domain": normalized_domain,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "risk_label": risk_label,
        "classification": classification,
        "is_legitimate_url": is_legitimate,
        "is_verified_legitimate": is_verified_legitimate,
        "reasons": unique_preserve_order(summary_reasons),
        "signals": {
            **signals,
            "suspicious_score": suspicious_score,
            "benign_score": benign_score,
            "effective_risk_score": risk_score,
        },
        "is_known_phishing": known_match,
    }


# ------------------------- Domain normalization -------------------------- #

def normalize_domain(value: str) -> Optional[str]:
    if not value:
        return None

    candidate = value.strip()
    if "://" not in candidate:
        candidate = f"http://{candidate}"

    try:
        parsed = parse.urlparse(candidate)
        host = parsed.hostname
    except Exception:
        host = None

    if not host:
        return None

    host = host.strip(".").lower()
    if host.startswith("www."):
        host = host[4:]

    if not re.fullmatch(r"[a-z0-9.-]+", host):
        return None

    if "." not in host:
        return None

    return host


# ---------------------- Known phishing list handling --------------------- #

def refresh_known_phishing_domains(force: bool = False) -> int:
    global KNOWN_PHISHING_DOMAINS, KNOWN_PHISHING_LAST_REFRESH

    with KNOWN_PHISHING_LOCK:
        now = time.time()
        if not force and KNOWN_PHISHING_LAST_REFRESH and now - KNOWN_PHISHING_LAST_REFRESH < KNOWN_PHISHING_CACHE_TTL_SECONDS:
            return len(KNOWN_PHISHING_DOMAINS)

        cached = load_known_phishing_cache()
        if not force and cached:
            cached_at, domains = cached
            if now - cached_at < KNOWN_PHISHING_CACHE_TTL_SECONDS:
                KNOWN_PHISHING_DOMAINS = set(domains) | BUILTIN_KNOWN_PHISHING_DOMAINS
                KNOWN_PHISHING_LAST_REFRESH = cached_at
                return len(KNOWN_PHISHING_DOMAINS)

        fetched_domains: Set[str] = set()
        for feed_url in KNOWN_PHISHING_FEEDS:
            try:
                with urllib_request.urlopen(feed_url, timeout=HTTP_TIMEOUT_SECONDS) as response:
                    raw = response.read().decode("utf-8", errors="ignore")
                fetched_domains.update(extract_domains_from_feed(raw))
            except Exception:
                continue

        if fetched_domains:
            KNOWN_PHISHING_DOMAINS = fetched_domains | BUILTIN_KNOWN_PHISHING_DOMAINS
            KNOWN_PHISHING_LAST_REFRESH = now
            save_known_phishing_cache(now, KNOWN_PHISHING_DOMAINS)
        else:
            KNOWN_PHISHING_DOMAINS = BUILTIN_KNOWN_PHISHING_DOMAINS | {domain for domain in KNOWN_PHISHING_DOMAINS if domain}
            KNOWN_PHISHING_LAST_REFRESH = now

        return len(KNOWN_PHISHING_DOMAINS)


def extract_domains_from_feed(raw: str) -> Set[str]:
    domains: Set[str] = set()
    for line in raw.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue

        host = normalize_domain(entry)
        if host:
            domains.add(host)
    return domains


def load_known_phishing_cache() -> Optional[Tuple[float, Set[str]]]:
    try:
        with open(KNOWN_PHISHING_CACHE_FILE, "r", encoding="utf-8") as f:
            payload = json.load(f)
        fetched_at = float(payload.get("fetched_at", 0))
        domains = {normalize_domain(domain) for domain in payload.get("domains", [])}
        return fetched_at, {domain for domain in domains if domain}
    except Exception:
        return None


def save_known_phishing_cache(fetched_at: float, domains: Set[str]) -> None:
    try:
        with open(KNOWN_PHISHING_CACHE_FILE, "w", encoding="utf-8") as f:
            json.dump({"fetched_at": fetched_at, "domains": sorted(domains)}, f)
    except Exception:
        pass


def is_known_phishing_domain(domain: str) -> bool:
    if domain in KNOWN_PHISHING_DOMAINS:
        return True
    root = get_registered_domain(domain)
    return root in KNOWN_PHISHING_DOMAINS if root else False


# ------------------------- Heuristic analyzers --------------------------- #

def analyze_dns(domain: str) -> Tuple[int, int, List[str], List[str], Dict[str, object]]:
    signals: Dict[str, object] = {"dns_resolves": False, "resolved_ip_count": 0}
    reasons: List[str] = []
    benign_reasons: List[str] = []
    suspicious_score = 0
    benign_score = 0

    try:
        answers = socket.getaddrinfo(domain, None)
        ips = sorted({entry[4][0] for entry in answers if entry and entry[4]})
        signals["dns_resolves"] = bool(ips)
        signals["resolved_ip_count"] = len(ips)
        signals["resolved_ips"] = ips[:5]
        if ips:
            benign_score += 6
            benign_reasons.append("Domain resolves in DNS")
        else:
            suspicious_score += 14
            reasons.append("Domain does not currently resolve in DNS")
    except Exception:
        suspicious_score += 14
        reasons.append("Domain does not currently resolve in DNS")

    return suspicious_score, benign_score, reasons, benign_reasons, signals


def analyze_keywords(domain: str) -> Tuple[int, List[str], List[str]]:
    reasons: List[str] = []
    matched: List[str] = []
    raw_tokens = [token for token in re.split(r"[^a-zA-Z0-9]+", domain) if token]
    normalized_tokens = [candidate for token in raw_tokens for candidate in similarity_candidates(token)]

    for keyword in sorted(SUSPICIOUS_KEYWORDS):
        exact_found = keyword in domain
        lookalike_found = any(
            token == keyword or (similarity(token, keyword) >= 0.88 and token != keyword)
            for token in normalized_tokens
        )
        if exact_found or lookalike_found:
            matched.append(keyword)
            reasons.append(
                f"Contains suspicious keyword: {keyword}" if exact_found else f"Contains a lookalike of suspicious keyword: {keyword}"
            )

    matched = sorted(set(matched))
    score = 0
    if len(matched) == 1:
        score = 12
    elif len(matched) == 2:
        score = 22
    elif len(matched) >= 3:
        score = 32

    return score, unique_preserve_order(reasons), matched


def analyze_url_structure(domain: str) -> Tuple[int, List[str], Dict[str, object]]:
    score = 0
    reasons: List[str] = []
    parts = domain.split(".")
    hostname_parts = parts[:-2] if len(parts) > 2 else []
    hyphen_count = domain.count("-")
    digit_count = sum(char.isdigit() for char in domain)
    tld = parts[-1]
    suspicious_subdomain_lookalikes: List[str] = []

    if len(domain) >= 45:
        score += 14
        reasons.append("Domain is unusually long")
    elif len(domain) >= 30:
        score += 8
        reasons.append("Domain is moderately long")

    if len(hostname_parts) >= 4:
        score += 16
        reasons.append("Domain has many subdomains")
    elif len(hostname_parts) >= 2:
        score += 9
        reasons.append("Domain uses multiple subdomains")

    if hyphen_count >= 3:
        score += 12
        reasons.append("Domain uses excessive hyphens")
    elif hyphen_count >= 1:
        score += 4
        reasons.append("Domain contains a hyphen")

    if digit_count >= 3:
        score += 14
        reasons.append("Domain contains several digits")
    elif digit_count >= 1:
        score += 8
        reasons.append("Domain contains digits")

    for label in hostname_parts:
        label_variants = similarity_candidates(label)
        for keyword in {"login", "signin", "secure", "verify", "account", "update", "auth"}:
            if any(candidate == keyword or similarity(candidate, keyword) >= 0.88 for candidate in label_variants):
                suspicious_subdomain_lookalikes.append(keyword)
                break

    if suspicious_subdomain_lookalikes:
        score += 16
        reasons.append(f"Subdomain disguises suspicious keyword '{suspicious_subdomain_lookalikes[0]}'")

    if domain.startswith("xn--") or ".xn--" in domain:
        score += 25
        reasons.append("Domain uses punycode, which can enable homograph attacks")

    if tld in SUSPICIOUS_TLDS:
        score += 15
        reasons.append(f"Domain uses a higher-risk TLD: .{tld}")

    return score, unique_preserve_order(reasons), {
        "subdomain_count": len(hostname_parts),
        "hyphen_count": hyphen_count,
        "digit_count": digit_count,
        "tld": tld,
        "deceptive_subdomain_keyword": bool(suspicious_subdomain_lookalikes),
        "deceptive_subdomain_matches": suspicious_subdomain_lookalikes[:5],
    }


def analyze_brand_impersonation(domain: str) -> Tuple[int, int, List[str], List[str], Dict[str, object]]:
    suspicious_score = 0
    benign_score = 0
    reasons: List[str] = []
    benign_reasons: List[str] = []
    signals: Dict[str, object] = {}

    root = get_registered_domain(domain)
    normalized_sld = normalize_for_similarity(second_level_label(domain))
    tokens = [normalize_for_similarity(token) for token in re.split(r"[^a-zA-Z0-9]+", domain) if token]

    best_brand = None
    best_similarity = 0.0
    official_brand_domain = False

    for brand, official_domains in KNOWN_BRANDS.items():
        official_match = domain in official_domains or root in official_domains
        if official_match:
            official_brand_domain = True
            best_brand = brand
            best_similarity = 1.0
            benign_score = max(benign_score, 32)
            benign_reasons.append(f"Matches official domain for brand '{brand}'")
            continue

        brand_similarity = similarity(normalized_sld, brand)
        token_similarity = max((similarity(token, brand) for token in tokens), default=0.0)
        best_for_brand = max(brand_similarity, token_similarity)
        contains_brand = brand in normalized_sld or any(brand in token for token in tokens)
        near_brand = 0.84 <= best_for_brand < 1.0

        if contains_brand and root and root not in official_domains:
            suspicious_score = max(suspicious_score, 35)
            reasons.append(f"Domain references brand '{brand}' but is not an official domain")
        elif near_brand:
            suspicious_score = max(suspicious_score, 45 if best_for_brand >= 0.92 else 34)
            reasons.append(f"Domain looks similar to brand '{brand}' (possible typosquatting)")

        if best_for_brand > best_similarity:
            best_similarity = best_for_brand
            best_brand = brand

    signals["suspected_brand"] = best_brand
    signals["brand_similarity"] = round(best_similarity, 3)
    signals["official_brand_domain"] = official_brand_domain
    return suspicious_score, benign_score, unique_preserve_order(reasons), unique_preserve_order(benign_reasons), signals


def analyze_domain_age(domain: str) -> Tuple[int, int, List[str], List[str], Dict[str, object]]:
    suspicious_score = 0
    benign_score = 0
    reasons: List[str] = []
    benign_reasons: List[str] = []
    signals: Dict[str, object] = {"domain_creation_date": None, "domain_age_days": None}

    registration_date = get_domain_registration_date(domain)
    if not registration_date:
        return suspicious_score, benign_score, reasons, benign_reasons, signals

    age_days = max((datetime.now(timezone.utc) - registration_date).days, 0)
    signals["domain_creation_date"] = registration_date.isoformat()
    signals["domain_age_days"] = age_days

    if age_days <= 7:
        suspicious_score += 30
        reasons.append("Domain was registered within the last 7 days")
    elif age_days <= 30:
        suspicious_score += 22
        reasons.append("Domain was registered within the last 30 days")
    elif age_days <= 90:
        suspicious_score += 10
        reasons.append("Domain was registered within the last 90 days")
    elif age_days >= 3650:
        benign_score += 18
        benign_reasons.append("Domain has existed for many years")
    elif age_days >= 365:
        benign_score += 12
        benign_reasons.append("Domain is older than one year")

    return suspicious_score, benign_score, reasons, benign_reasons, signals


def analyze_tls_certificate(domain: str) -> Tuple[int, int, List[str], List[str], Dict[str, object]]:
    suspicious_score = 0
    benign_score = 0
    reasons: List[str] = []
    benign_reasons: List[str] = []
    signals: Dict[str, object] = {
        "tls_present": False,
        "tls_issuer": None,
        "tls_subject_org": None,
        "tls_not_before": None,
        "tls_certificate_age_days": None,
    }

    cert = get_tls_certificate(domain)
    if not cert:
        suspicious_score += 18
        reasons.append("Unable to validate a TLS certificate")
        return suspicious_score, benign_score, reasons, benign_reasons, signals

    signals["tls_present"] = True
    issuer = dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {}
    subject = dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {}
    issuer_name = issuer.get("organizationName") or issuer.get("commonName")
    subject_org = subject.get("organizationName")
    not_before_raw = cert.get("notBefore")

    signals["tls_issuer"] = issuer_name
    signals["tls_subject_org"] = subject_org
    signals["tls_not_before"] = not_before_raw

    if not subject_org:
        suspicious_score += 12
        reasons.append("TLS certificate does not include organization information")
    else:
        benign_score += 8
        benign_reasons.append("TLS certificate includes organization information")

    not_before = parse_certificate_time(not_before_raw)
    if not_before:
        age_days = max((datetime.now(timezone.utc) - not_before).days, 0)
        signals["tls_certificate_age_days"] = age_days
        if age_days <= 7:
            suspicious_score += 12
            reasons.append("TLS certificate was issued very recently")
        elif age_days <= 30:
            suspicious_score += 7
            reasons.append("TLS certificate is relatively new")
        elif age_days >= 180:
            benign_score += 5
            benign_reasons.append("TLS certificate is not newly issued")

    return suspicious_score, benign_score, reasons, benign_reasons, signals


def analyze_page_content(domain: str) -> Tuple[int, int, List[str], List[str], Dict[str, object]]:
    suspicious_score = 0
    benign_score = 0
    reasons: List[str] = []
    benign_reasons: List[str] = []
    signals: Dict[str, object] = {
        "page_retrieved": False,
        "password_field_detected": False,
        "form_count": 0,
        "page_brand_terms": [],
        "page_title": None,
        "page_has_login_language": False,
        "redirected_to_different_host": False,
    }

    html, final_url = fetch_page(domain)
    if not html:
        return suspicious_score, benign_score, reasons, benign_reasons, signals

    lowered = html.lower()
    signals["page_retrieved"] = True
    signals["page_title"] = extract_title(html)
    signals["form_count"] = len(re.findall(r"<form\b", lowered))

    password_field_detected = bool(re.search(r'<input[^>]+type=["\']?password', lowered))
    signals["password_field_detected"] = password_field_detected
    if password_field_detected:
        suspicious_score += 24
        reasons.append("Page contains a password input field")

    brand_terms = [brand for brand in KNOWN_BRANDS if brand in lowered][:6]
    signals["page_brand_terms"] = brand_terms

    login_language = any(term in lowered for term in SUSPICIOUS_PHRASES) or any(
        term in lowered for term in ["sign in", "log in", "login", "password", "username", "two-factor", "multi-factor", "one-time code"]
    )
    signals["page_has_login_language"] = login_language
    if login_language:
        suspicious_score += 10
        reasons.append("Page contains login or account-verification language")

    normalized_final = normalize_domain(final_url) if final_url else None
    redirected = bool(normalized_final and normalized_final != domain)
    signals["redirected_to_different_host"] = redirected
    if redirected:
        suspicious_score += 8
        reasons.append("Domain redirects to a different host")

    if brand_terms:
        root = get_registered_domain(domain)
        official = any(domain.endswith(official) or (root and root == official) for brand in brand_terms for official in KNOWN_BRANDS[brand])
        if official:
            benign_score += 12
            benign_reasons.append("Page branding matches the official domain")
        else:
            suspicious_score += 22
            reasons.append("Page content references a known brand on a non-official domain")

    title = (signals["page_title"] or "").lower()
    if any(term in title for term in ["404", "not found", "coming soon", "parking"]):
        suspicious_score += 4
        reasons.append("Site title suggests a temporary or parked page")

    return suspicious_score, benign_score, reasons, benign_reasons, signals


# --------------------------- External lookups ---------------------------- #

def get_domain_registration_date(domain: str) -> Optional[datetime]:
    root = get_registered_domain(domain)
    if not root:
        return None
    url = f"https://rdap.org/domain/{root}"
    try:
        with urllib_request.urlopen(url, timeout=HTTP_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8", errors="ignore"))
    except Exception:
        return None

    for event in payload.get("events", []):
        action = str(event.get("eventAction", "")).lower()
        if action in {"registration", "registered", "creation", "created"}:
            parsed = parse_datetime(event.get("eventDate"))
            if parsed:
                return parsed
    return None


def get_tls_certificate(domain: str) -> Optional[dict]:
    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=SOCKET_TIMEOUT_SECONDS) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:
                return secure_sock.getpeercert()
    except Exception:
        return None


def fetch_page(domain: str) -> Tuple[Optional[str], Optional[str]]:
    headers = {"User-Agent": "Mozilla/5.0 (compatible; PhishingIntelPipeline/1.1)"}
    for scheme in ("https", "http"):
        url = f"{scheme}://{domain}"
        req = urllib_request.Request(url, headers=headers)
        try:
            with urllib_request.urlopen(req, timeout=HTTP_TIMEOUT_SECONDS) as response:
                content_type = response.headers.get("Content-Type", "")
                if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
                    return None, str(response.geturl())
                html = response.read(250_000).decode("utf-8", errors="ignore")
                return html, str(response.geturl())
        except error.HTTPError as exc:
            try:
                html = exc.read(250_000).decode("utf-8", errors="ignore")
                if html:
                    return html, url
            except Exception:
                pass
        except Exception:
            continue
    return None, None


# ------------------------------- Helpers --------------------------------- #

def get_registered_domain(domain: str) -> Optional[str]:
    parts = domain.split(".")
    if len(parts) < 2:
        return None
    common_second_level_suffixes = {
        "co.uk", "org.uk", "gov.uk", "ac.uk",
        "com.au", "net.au", "org.au",
        "co.jp", "com.br", "com.mx",
    }
    if len(parts) >= 3 and ".".join(parts[-2:]) in {suffix.split('.', 1)[1] for suffix in common_second_level_suffixes if '.' in suffix}:
        candidate = ".".join(parts[-3:])
        if candidate in common_second_level_suffixes and len(parts) >= 4:
            return ".".join(parts[-4:])
    return ".".join(parts[-2:])


def second_level_label(domain: str) -> str:
    root = get_registered_domain(domain)
    if not root:
        return domain
    return root.split(".")[0]


def normalize_for_similarity(text: str) -> str:
    lowered = text.lower().translate(LEET_TRANSLATION)
    return re.sub(r"[^a-z0-9]", "", lowered)


def similarity(a: str, b: str) -> float:
    if not a or not b:
        return 0.0
    return SequenceMatcher(None, a, b).ratio()


def similarity_candidates(text: str) -> List[str]:
    variants = {
        normalize_for_similarity(text),
        re.sub(r"[^a-z0-9]", "", text.lower().translate(ALT_LEET_TRANSLATION)),
        re.sub(r"[^a-z0-9]", "", text.lower()),
    }
    return [item for item in variants if item]


def parse_datetime(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    value = value.strip()
    try:
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except Exception:
        return None


def parse_certificate_time(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    for fmt in ("%b %d %H:%M:%S %Y %Z", "%Y%m%d%H%M%SZ"):
        try:
            return datetime.strptime(value, fmt).replace(tzinfo=timezone.utc)
        except Exception:
            continue
    return None


def extract_title(html: str) -> Optional[str]:
    match = re.search(r"<title[^>]*>(.*?)</title>", html, re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    title = unescape(re.sub(r"\s+", " ", match.group(1))).strip()
    return title[:200] if title else None


def unique_preserve_order(items: List[str]) -> List[str]:
    return list(dict.fromkeys(items))


def classify_domain(
    risk_score: int,
    suspicious_score: int,
    benign_score: int,
    known_match: bool,
    signals: Dict[str, object],
) -> Tuple[str, bool, bool]:
    if known_match or risk_score >= 60:
        return "phishing", False, False
    if risk_score >= 30:
        return "suspicious", False, False

    official_brand = bool(signals.get("official_brand_domain"))
    domain_age_days = signals.get("domain_age_days")
    old_domain = isinstance(domain_age_days, int) and domain_age_days >= 365
    dns_resolves = bool(signals.get("dns_resolves"))
    tls_present = bool(signals.get("tls_present"))
    password_field = bool(signals.get("password_field_detected"))
    login_language = bool(signals.get("page_has_login_language"))
    brand_similarity = float(signals.get("brand_similarity", 0) or 0)
    deceptive_subdomain = bool(signals.get("deceptive_subdomain_keyword"))
    matched_keywords = signals.get("matched_keywords") or []
    suspected_brand = signals.get("suspected_brand")

    # Only zero out the score when legitimacy is strongly confirmed.
    if risk_score <= 12 and benign_score >= 18 and dns_resolves and tls_present and not password_field and not login_language and not deceptive_subdomain and brand_similarity < 0.84 and (official_brand or old_domain) and len(matched_keywords) <= 1:
        return "legitimate", True, True

    if risk_score <= 29 and benign_score >= 12 and dns_resolves and not password_field and not deceptive_subdomain and brand_similarity < 0.84:
        return "low_risk", False, False

    return "low_risk", False, False


def risk_score_to_level(score: int, classification: str) -> str:
    if classification == "legitimate":
        return "legitimate"
    if score >= 60:
        return "likely_phishing"
    if score >= 30:
        return "suspicious"
    return "low_risk"


def classification_to_display_label(classification: str) -> str:
    mapping = {
        "phishing": "Likely phishing",
        "suspicious": "Suspicious",
        "legitimate": "Legitimate",
        "low_risk": "Low risk",
        "invalid": "Invalid",
    }
    return mapping.get(classification, classification.replace("_", " ").title())


try:
    refresh_known_phishing_domains(force=False)
except Exception:
    pass
