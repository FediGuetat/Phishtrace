import re
from dataclasses import dataclass
from email.utils import parseaddr
from enum import IntEnum
from urllib.parse import urlparse

from phishtrace.parser import ParsedEmail

# only compare when the text looks like an address click here has nothing to compare
DOMAIN_LIKE = re.compile(
    r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?$", re.IGNORECASE
)

# brands send from several domains keep these complete or real mail gets flagged
# no gmail.com or amazonses.com in here anyone can send from those
BRANDS = {
    "paypal": ["paypal.com"],
    "microsoft": [
        "microsoft.com",
        "microsoftonline.com",
        "outlook.com",
        "office.com",
        "office365.com",
        "live.com",
    ],
    "apple": ["apple.com", "icloud.com"],
    "amazon": [
        "amazon.com",
        "amazon.co.uk",
        "amazon.de",
        "amazon.fr",
        "amazon.it",
        "amazon.es",
        "amazon.ca",
    ],
    "google": ["google.com"],
    "netflix": ["netflix.com"],
    "dhl": ["dhl.com", "dhl.de"],
    "facebook": ["facebook.com", "facebookmail.com"],
    "meta": ["meta.com", "facebook.com", "facebookmail.com"],
    "instagram": ["instagram.com", "facebookmail.com"],
    "linkedin": ["linkedin.com"],
}

LOOKALIKES = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l")]


class Severity(IntEnum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3


@dataclass
class Finding:
    name: str
    severity: Severity
    detail: str


def check_link_mismatch(email: ParsedEmail) -> list[Finding]:
    findings = []
    for link in email.links:
        if not DOMAIN_LIKE.match(link.text):
            continue
        shown = _host(link.text)
        real = _host(link.url)
        if not real:
            continue
        if _is_within(real, shown):
            continue
        detail = f"link shows {shown} but goes to {real}"
        findings.append(Finding("link_mismatch", Severity.HIGH, detail))
    return findings


def check_reply_to_mismatch(email: ParsedEmail) -> list[Finding]:
    sender = _email_domain(email.sender)
    reply_to = _email_domain(email.reply_to)
    if not sender or not reply_to:
        return []
    if _same_org(sender, reply_to):
        return []
    detail = f"replies go to {reply_to} instead of {sender}"
    return [Finding("reply_to_mismatch", Severity.MEDIUM, detail)]


def check_brand_impersonation(email: ParsedEmail) -> list[Finding]:
    name, _ = parseaddr(email.sender)
    sender = _email_domain(email.sender)
    if not name or not sender:
        return []

    findings = []
    for brand, domains in BRANDS.items():
        # word match so metadata team doesnt count as meta
        if not re.search(rf"\b{brand}\b", name, re.IGNORECASE):
            continue
        if any(_is_within(sender, domain) for domain in domains):
            continue
        detail = f"display name says {brand} but mail comes from {sender}"
        findings.append(Finding("brand_impersonation", Severity.HIGH, detail))
    return findings


def check_lookalike_domain(email: ParsedEmail) -> list[Finding]:
    domains = [_email_domain(email.sender), _email_domain(email.reply_to)]
    domains += [_host(link.url) for link in email.links]

    findings = []
    # dedupe but keep the order
    for domain in dict.fromkeys(domains):
        if not domain or _is_official(domain):
            continue
        if any(label.startswith("xn--") for label in domain.split(".")):
            detail = f"{domain} uses punycode which can hide lookalike letters"
            findings.append(Finding("lookalike_domain", Severity.HIGH, detail))
            continue
        brand = _hidden_brand(domain)
        if brand:
            detail = f"{domain} looks like {brand}"
            findings.append(Finding("lookalike_domain", Severity.HIGH, detail))
    return findings


def _hidden_brand(domain: str) -> str:
    unmasked = domain
    for fake, real in LOOKALIKES:
        unmasked = unmasked.replace(fake, real)
    # only counts if swapping the fake letters is what reveals the brand
    for brand in BRANDS:
        if brand in unmasked and brand not in domain:
            return brand
    return ""


def _is_official(domain: str) -> bool:
    return any(
        _is_within(domain, official)
        for officials in BRANDS.values()
        for official in officials
    )


def _email_domain(address: str) -> str:
    _, addr = parseaddr(address)
    if "@" not in addr:
        return ""
    return addr.rpartition("@")[2].lower()


def _same_org(a: str, b: str) -> bool:
    # mail.company.com replying to company.com is still the same org
    return _is_within(a, b) or _is_within(b, a)


def _is_within(domain: str, parent: str) -> bool:
    # login.paypal.com is fine for paypal.com but paypal.com.evil.ru isnt
    return domain == parent or domain.endswith("." + parent)


def _host(url: str) -> str:
    # urlparse needs a scheme or it treats the whole thing as a path
    if "://" not in url:
        url = "http://" + url
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return ""
    return host.removeprefix("www.")


RULES = [
    check_link_mismatch,
    check_reply_to_mismatch,
    check_brand_impersonation,
    check_lookalike_domain,
]


def run_all_rules(email: ParsedEmail) -> list[Finding]:
    findings = []
    for rule in RULES:
        findings.extend(rule(email))
    return findings
