import re
from dataclasses import dataclass
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser

from bs4 import BeautifulSoup

URL_PATTERN = re.compile(r"https?://[^\s<>\"']+")
AUTH_PATTERN = re.compile(r"\b(spf|dkim|dmarc)=(\w+)", re.IGNORECASE)


@dataclass
class Link:
    # text is what the user sees url is where it actually goes
    text: str
    url: str


@dataclass
class Attachment:
    filename: str
    # whatever the sender claims so it can lie
    content_type: str
    size: int


@dataclass
class AuthResults:
    # empty means unknown not fail pasted emails lose headers all the time
    spf: str = ""
    dkim: str = ""
    dmarc: str = ""


@dataclass
class ParsedEmail:
    sender: str
    reply_to: str
    subject: str
    body: str
    links: list[Link]
    attachments: list[Attachment]
    auth: AuthResults


def parse_email(raw: bytes) -> ParsedEmail:
    # need policy.default the legacy one doesnt decode headers or have get_body()
    message = BytesParser(policy=policy.default).parsebytes(raw)
    body, links = _extract_content(message)

    return ParsedEmail(
        sender=str(message.get("From", "")),
        reply_to=str(message.get("Reply-To", "")),
        subject=str(message.get("Subject", "")),
        body=body,
        links=links,
        attachments=_extract_attachments(message),
        auth=_extract_auth(message),
    )


def _extract_content(message: EmailMessage) -> tuple[str, list[Link]]:
    # html first thats what people actually see plain part can be a decoy
    part = message.get_body(preferencelist=("html", "plain"))
    if part is None:
        return "", []

    content = part.get_content().replace("\r\n", "\n")
    if part.get_content_type() == "text/html":
        soup = BeautifulSoup(content, "html.parser")
        return _html_to_text(soup), _html_links(soup)
    return content, _plain_links(content)


def _html_to_text(soup: BeautifulSoup) -> str:
    for tag in soup(["script", "style"]):
        tag.decompose()
    # without the space your <b>account</b> ends up as youraccount
    return soup.get_text(separator=" ", strip=True)


def _html_links(soup: BeautifulSoup) -> list[Link]:
    return [
        Link(text=a.get_text(" ", strip=True), url=a["href"].strip())
        for a in soup.find_all("a", href=True)
    ]


def _extract_attachments(message: EmailMessage) -> list[Attachment]:
    attachments = []
    # walk() not iter_attachments() that one misses nested parts
    for part in message.walk():
        filename = part.get_filename()
        if not filename:
            continue
        # just need the size dont keep the content around
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            Attachment(
                filename=filename,
                content_type=part.get_content_type(),
                size=len(payload),
            )
        )
    return attachments


def _extract_auth(message: EmailMessage) -> AuthResults:
    # only the top header is from our own provider anything below can be faked
    header = str(message.get("Authentication-Results", ""))
    results = {}
    for method, value in AUTH_PATTERN.findall(header):
        results.setdefault(method.lower(), value.lower())
    return AuthResults(**results)


def _plain_links(text: str) -> list[Link]:
    links = []
    for match in URL_PATTERN.finditer(text):
        # urls at the end of a sentence pick up the period
        url = match.group().rstrip(".,;:!?)")
        links.append(Link(text=url, url=url))
    return links
