from pathlib import Path

from phishtrace.parser import Attachment, AuthResults, Link, parse_email

FIXTURES = Path(__file__).parent / "fixtures"


def test_parse_simple_email():
    raw = (FIXTURES / "simple.eml").read_bytes()

    parsed = parse_email(raw)

    assert parsed.sender == "PayPal Support <support@paypa1-security.com>"
    assert parsed.reply_to == "billing@random-domain.ru"
    assert parsed.subject == "Your account has been suspended"
    assert "Verify your account within 24 hours" in parsed.body


def test_missing_headers_give_empty_strings():
    parsed = parse_email(b"From: a@example.com\n\nHello")

    assert parsed.reply_to == ""
    assert parsed.subject == ""
    assert parsed.body == "Hello"


def test_encoded_subject_is_decoded():
    raw = b"Subject: =?utf-8?b?VXJnZW50OiBhY3Rpb24gcmVxdWlyZWQ=?=\n\nHi"

    parsed = parse_email(raw)

    assert parsed.subject == "Urgent: action required"


def test_html_body_is_converted_to_text():
    raw = (
        b"Content-Type: text/html\n\n"
        b"<html><head><style>p { color: red; }</style></head>"
        b"<body><p>Verify your <b>account</b> now</p>"
        b"<script>alert(1)</script></body></html>"
    )

    parsed = parse_email(raw)

    assert parsed.body == "Verify your account now"


def test_html_part_preferred_over_plain():
    raw = (FIXTURES / "multipart.eml").read_bytes()

    parsed = parse_email(raw)

    # plain part is the decoy here
    assert parsed.body == "Your password expires today. Keep current password"
    assert "newsletter" not in parsed.body


def test_windows_line_endings_are_normalized():
    parsed = parse_email(b"From: a@example.com\r\n\r\nLine one\r\nLine two\r\n")

    assert parsed.body == "Line one\nLine two\n"


def test_links_from_html():
    parsed = parse_email((FIXTURES / "multipart.eml").read_bytes())

    assert parsed.links == [
        Link(text="Keep current password", url="http://micros0ft-support.com/reset")
    ]


def test_links_from_plain_text():
    parsed = parse_email((FIXTURES / "simple.eml").read_bytes())

    url = "http://paypa1-security.com/login"
    assert parsed.links == [Link(text=url, url=url)]


def test_no_links():
    parsed = parse_email(b"From: a@example.com\n\nHello")

    assert parsed.links == []


def test_anchor_without_href_is_skipped():
    raw = (
        b"Content-Type: text/html\n\n"
        b'<a name="top">Top</a><a href="https://example.com">Go</a>'
    )

    parsed = parse_email(raw)

    assert parsed.links == [Link(text="Go", url="https://example.com")]


def test_trailing_period_is_not_part_of_url():
    parsed = parse_email(b"From: a@example.com\n\nLog in at https://example.com/login.")

    assert parsed.links[0].url == "https://example.com/login"


def test_attachment_metadata():
    parsed = parse_email((FIXTURES / "attachment.eml").read_bytes())

    assert parsed.attachments == [
        Attachment(filename="invoice.pdf.exe", content_type="application/pdf", size=12)
    ]


def test_attachment_does_not_break_body_or_links():
    parsed = parse_email((FIXTURES / "attachment.eml").read_bytes())

    assert parsed.body == "Please see the attached invoice or pay online ."
    assert parsed.links == [
        Link(text="pay online", url="http://invoices-online.net/pay")
    ]


def test_no_attachments():
    parsed = parse_email(b"From: a@example.com\n\nHello")

    assert parsed.attachments == []


def test_auth_results():
    raw = (
        b"Authentication-Results: mx.google.com; spf=pass smtp.mailfrom=x.com;"
        b" dkim=fail header.d=x.com; dmarc=fail header.from=paypal.com\n\nHi"
    )

    parsed = parse_email(raw)

    assert parsed.auth == AuthResults(spf="pass", dkim="fail", dmarc="fail")


def test_missing_auth_header_is_unknown():
    parsed = parse_email(b"From: a@example.com\n\nHi")

    assert parsed.auth == AuthResults(spf="", dkim="", dmarc="")


def test_only_top_auth_header_counts():
    raw = (
        b"Authentication-Results: mx.google.com; spf=fail; dkim=none; dmarc=fail\n"
        b"Authentication-Results: fake.example; spf=pass; dkim=pass; dmarc=pass\n\nHi"
    )

    parsed = parse_email(raw)

    assert parsed.auth == AuthResults(spf="fail", dkim="none", dmarc="fail")


def test_auth_values_are_lowercased():
    parsed = parse_email(b"Authentication-Results: mx; SPF=Pass\n\nHi")

    assert parsed.auth.spf == "pass"
