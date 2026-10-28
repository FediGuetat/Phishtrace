import re
from dataclasses import dataclass
from enum import IntEnum
from urllib.parse import urlparse

from phishtrace.parser import ParsedEmail

# only compare when the text looks like an address click here has nothing to compare
DOMAIN_LIKE = re.compile(
    r"^(https?://)?([a-z0-9-]+\.)+[a-z]{2,}(/\S*)?$", re.IGNORECASE
)


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
        # login.paypal.com is fine for paypal.com but paypal.com.evil.ru isnt
        if real == shown or real.endswith("." + shown):
            continue
        detail = f"link shows {shown} but goes to {real}"
        findings.append(Finding("link_mismatch", Severity.HIGH, detail))
    return findings


def _host(url: str) -> str:
    # urlparse needs a scheme or it treats the whole thing as a path
    if "://" not in url:
        url = "http://" + url
    try:
        host = urlparse(url).hostname or ""
    except ValueError:
        return ""
    return host.removeprefix("www.")


RULES = [check_link_mismatch]


def run_all_rules(email: ParsedEmail) -> list[Finding]:
    findings = []
    for rule in RULES:
        findings.extend(rule(email))
    return findings
