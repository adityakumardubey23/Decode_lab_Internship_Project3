import ipaddress
import re
from urllib.parse import urlparse

URL_RE = re.compile(r"""(?i)\b(?:https?://|www\.)[^\s<>()\[\]{}"']+""")
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "rb.gy", "cutt.ly", "shorturl.at"}
BRAND_WORDS = {"paypal", "microsoft", "google", "amazon", "apple", "netflix", "bank"}


def extract_urls(text):
    return [item.rstrip(".,;:!?") for item in URL_RE.findall(text)]


def inspect_url(url):
    normalized = url if "://" in url else "http://" + url
    parsed = urlparse(normalized)
    host = (parsed.hostname or "").lower().strip(".")
    findings = []
    if not host:
        return findings

    def add(name, explanation, points=2, severity="medium"):
        findings.append({
            "name": name,
            "explanation": f"{explanation} URL: {url}",
            "points": points,
            "severity": severity,
        })

    if parsed.scheme.lower() == "http":
        add("Unencrypted HTTP link", "The link does not use HTTPS.", 1, "low")
    if host in SHORTENERS:
        add("URL shortener", "A shortened URL hides the final destination.", 2)
    try:
        ipaddress.ip_address(host)
        add("IP-address URL", "The link uses a raw IP address instead of a normal domain.", 3, "high")
    except ValueError:
        pass
    if host.startswith("xn--") or ".xn--" in host:
        add("Punycode domain", "The domain contains a punycode label that may disguise lookalike characters.", 3, "high")
    if host.count(".") >= 3:
        add("Deeply nested subdomain", "Several subdomain levels can make the true domain harder to notice.", 1, "low")
    try:
        if parsed.port and parsed.port not in (80, 443):
            add("Unusual URL port", f"The link uses non-standard web port {parsed.port}.", 1, "low")
    except ValueError:
        add("Malformed URL port", "The URL contains an invalid port value.", 2)

    labels = host.split(".")
    registered_looking = ".".join(labels[-2:]) if len(labels) >= 2 else host
    for brand in BRAND_WORDS:
        if brand in host and brand not in registered_looking:
            add("Possible brand-in-subdomain trick",
                f"The brand-like word '{brand}' appears outside the final domain labels.", 2)
            break
    if "@" in parsed.netloc:
        add("At-sign in URL authority", "An at-sign can obscure which host a URL targets.", 2)
    return findings


def analyze_urls(text):
    findings = []
    for url in extract_urls(text):
        findings.extend(inspect_url(url))
    return findings
