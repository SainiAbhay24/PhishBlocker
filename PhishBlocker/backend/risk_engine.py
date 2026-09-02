"""
PhishBlocker - URL Risk Engine
--------------------------------
Defensive, rule-based URL analyzer. Combines multiple weak signals into a
single confidence-weighted risk score (0-100). No signal is treated as
absolute truth -- this mirrors how real products (SafeBrowsing, phishing
gateways, EDR URL filters) work: layered heuristics, not a single verdict.

This module does NOT perform any offensive action. It only inspects a
URL string and known-pattern lists; it never navigates to, fetches,
or interacts with the destination.
"""
import re
from urllib.parse import urlparse
from typing import List, Tuple
from models import SignalHit

# ---------------------------------------------------------------------
# Reference data (in a real product this would be pulled from a threat
# intel feed / reputation DB -- kept local + static here for the prototype)
# ---------------------------------------------------------------------

KNOWN_URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd",
    "buff.ly", "rebrand.ly", "cutt.ly", "shorte.st",
}

CREDENTIAL_HARVEST_KEYWORDS = [
    "verify-account", "confirm-identity", "update-billing", "login-secure",
    "account-locked", "signin-verify", "password-reset", "wallet-verify",
    "banking-alert", "security-check", "unlock-account", "suspended-account",
]

BRAND_IMPERSONATION_TARGETS = [
    "paypal", "microsoft", "office365", "apple", "amazon", "netflix",
    "chase", "bankofamerica", "wellsfargo", "google", "outlook", "irs",
]

SUSPICIOUS_TLDS = {
    ".zip", ".mov", ".xyz", ".top", ".gq", ".tk", ".ml", ".cf", ".work",
    ".click", ".link", ".rest",
}

IP_URL_REGEX = re.compile(r"^https?://\d{1,3}(\.\d{1,3}){3}")
PUNYCODE_REGEX = re.compile(r"xn--")
EXCESSIVE_HYPHEN_REGEX = re.compile(r"-.*-.*-")
EXCESSIVE_SUBDOMAIN_REGEX = re.compile(r"^(?:[^.]+\.){4,}[^.]+$")


def _check_https(parsed) -> Tuple[int, str] | None:
    if parsed.scheme != "https":
        return 12, f"Non-HTTPS scheme used ('{parsed.scheme}') — traffic may be unencrypted"
    return None


def _check_ip_based_url(url: str) -> Tuple[int, str] | None:
    if IP_URL_REGEX.match(url):
        return 25, "URL uses a raw IP address instead of a domain name"
    return None


def _check_punycode(host: str) -> Tuple[int, str] | None:
    if PUNYCODE_REGEX.search(host):
        return 30, "Punycode encoding detected — possible homograph/lookalike domain attack"
    return None


def _check_shortener(host: str) -> Tuple[int, str] | None:
    if host in KNOWN_URL_SHORTENERS:
        return 15, f"'{host}' is a known URL shortener — true destination is hidden"
    return None


def _check_credential_keywords(url_lower: str) -> Tuple[int, str] | None:
    hits = [kw for kw in CREDENTIAL_HARVEST_KEYWORDS if kw in url_lower]
    if hits:
        return 28, f"Credential-harvesting phrasing detected: {', '.join(hits[:3])}"
    return None


def _check_brand_impersonation(host: str) -> Tuple[int, str] | None:
    """Flags a brand name appearing in the hostname alongside a domain that
    is NOT the brand's real registered domain (classic lookalike pattern)."""
    for brand in BRAND_IMPERSONATION_TARGETS:
        if brand in host and not host.endswith(f"{brand}.com"):
            return 22, f"Hostname references brand '{brand}' but is not its official domain"
    return None


def _check_suspicious_tld(host: str) -> Tuple[int, str] | None:
    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            return 10, f"Domain uses a TLD frequently abused for phishing ('{tld}')"
    return None


def _check_excessive_hyphens(host: str) -> Tuple[int, str] | None:
    if EXCESSIVE_HYPHEN_REGEX.search(host):
        return 8, "Domain contains an unusually high number of hyphens"
    return None


def _check_excessive_subdomains(host: str) -> Tuple[int, str] | None:
    if EXCESSIVE_SUBDOMAIN_REGEX.match(host):
        return 12, "Domain has an excessive number of subdomain levels (common obfuscation trick)"
    return None


def _check_url_length(url: str) -> Tuple[int, str] | None:
    if len(url) > 120:
        return 6, f"URL is unusually long ({len(url)} chars) — may hide payload/obfuscation"
    return None


def _check_at_symbol(url: str) -> Tuple[int, str] | None:
    # http://real-looking-site.com@evil.com/... browsers navigate to evil.com
    if "@" in urlparse(url).netloc:
        return 20, "URL authority contains '@' — classic browser redirection trick"
    return None


# Ordered list of (check_fn, needs) — 'needs' tells us what to pass in
CHECKS = [
    (_check_https, "parsed"),
    (_check_ip_based_url, "url"),
    (_check_punycode, "host"),
    (_check_shortener, "host"),
    (_check_credential_keywords, "url_lower"),
    (_check_brand_impersonation, "host"),
    (_check_suspicious_tld, "host"),
    (_check_excessive_hyphens, "host"),
    (_check_excessive_subdomains, "host"),
    (_check_url_length, "url"),
    (_check_at_symbol, "url"),
]


def classify(score: int) -> Tuple[str, str]:
    """Maps a numeric score to (verdict, severity) per the roadmap's
    risk scoring model (section 15 of the project doc)."""
    if score >= 80:
        return "BLOCK", "CRITICAL"
    if score >= 60:
        return "WARN", "HIGH"
    if score >= 35:
        return "WARN", "MEDIUM"
    return "SAFE", "LOW"


def guess_category(signals: List[SignalHit]) -> str | None:
    names = {s.name for s in signals}
    if "credential_keywords" in names or "brand_impersonation" in names:
        return "Credential Harvesting"
    if "punycode" in names or "excessive_subdomains" in names:
        return "Homograph / Lookalike Domain"
    if "ip_based_url" in names or "at_symbol" in names:
        return "Redirection / Obfuscation"
    return None


def analyze_url(url: str) -> dict:
    """
    Runs all heuristic checks against a URL and returns a risk report.
    Never fetches or navigates to the URL -- pure string/pattern analysis.
    """
    url = url.strip()
    parsed = urlparse(url if "://" in url else f"http://{url}")
    host = parsed.netloc.lower().split("@")[-1]  # strip userinfo if present
    url_lower = url.lower()

    context = {
        "parsed": parsed,
        "url": url,
        "host": host,
        "url_lower": url_lower,
    }

    signals: List[SignalHit] = []
    total = 0

    for check_fn, needs in CHECKS:
        result = check_fn(context[needs])
        if result:
            weight, detail = result
            signals.append(SignalHit(name=check_fn.__name__.replace("_check_", ""),
                                      weight=weight, detail=detail))
            total += weight

    score = min(total, 100)
    verdict, severity = classify(score)
    category = guess_category(signals)

    return {
        "url": url,
        "risk_score": score,
        "verdict": verdict,
        "severity": severity,
        "signals": signals,
        "threat_category": category,
    }
