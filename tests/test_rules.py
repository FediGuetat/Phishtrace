from pathlib import Path

from phishtrace.parser import parse_email
from phishtrace.rules import (
    Finding,
    Severity,
    check_link_mismatch,
    check_reply_to_mismatch,
    run_all_rules,
)

FIXTURES = Path(__file__).parent / "fixtures"


def _email_with_link(text, href):
    raw = f'Content-Type: text/html\n\n<a href="{href}">{text}</a>'
    return parse_email(raw.encode())


def test_link_to_other_domain_is_flagged():
    email = _email_with_link("www.paypal.com", "http://evil.ru/login")

    detail = "link shows paypal.com but goes to evil.ru"
    assert check_link_mismatch(email) == [
        Finding("link_mismatch", Severity.HIGH, detail)
    ]


def test_link_to_same_domain_is_fine():
    email = _email_with_link("https://paypal.com", "https://paypal.com/login")

    assert check_link_mismatch(email) == []


def test_www_on_one_side_is_fine():
    email = _email_with_link("www.paypal.com", "https://paypal.com")

    assert check_link_mismatch(email) == []


def test_real_subdomain_is_fine():
    email = _email_with_link("paypal.com", "https://login.paypal.com/x")

    assert check_link_mismatch(email) == []


def test_brand_used_as_subdomain_is_flagged():
    email = _email_with_link("paypal.com", "http://paypal.com.evil.ru")

    assert len(check_link_mismatch(email)) == 1


def test_at_sign_trick_is_flagged():
    email = _email_with_link("paypal.com", "http://paypal.com@evil.ru")

    detail = check_link_mismatch(email)[0].detail
    assert detail == "link shows paypal.com but goes to evil.ru"


def test_case_does_not_matter():
    email = _email_with_link("PayPal.com", "https://paypal.com")

    assert check_link_mismatch(email) == []


def test_text_that_is_not_an_address_is_skipped():
    email = _email_with_link("Click here", "http://evil.ru")

    assert check_link_mismatch(email) == []


def test_plain_text_links_are_never_flagged():
    email = parse_email((FIXTURES / "simple.eml").read_bytes())

    assert check_link_mismatch(email) == []


def test_run_all_rules_collects_findings():
    email = _email_with_link("paypal.com", "http://evil.ru")

    assert run_all_rules(email) == check_link_mismatch(email)


def _email_with_headers(sender, reply_to):
    return parse_email(f"From: {sender}\nReply-To: {reply_to}\n\nHi".encode())


def test_reply_to_other_domain_is_flagged():
    email = parse_email((FIXTURES / "simple.eml").read_bytes())

    detail = "replies go to random-domain.ru instead of paypa1-security.com"
    assert check_reply_to_mismatch(email) == [
        Finding("reply_to_mismatch", Severity.MEDIUM, detail)
    ]


def test_no_reply_to_is_fine():
    email = parse_email(b"From: a@example.com\n\nHi")

    assert check_reply_to_mismatch(email) == []


def test_reply_to_same_domain_is_fine():
    email = _email_with_headers("Shop <news@shop.com>", "support@shop.com")

    assert check_reply_to_mismatch(email) == []


def test_reply_to_subdomain_is_fine():
    email = _email_with_headers("news@mail.shop.com", "Support <help@shop.com>")

    assert check_reply_to_mismatch(email) == []


def test_reply_to_case_does_not_matter():
    email = _email_with_headers("a@Shop.com", "b@SHOP.COM")

    assert check_reply_to_mismatch(email) == []


def test_reply_to_without_address_is_skipped():
    email = _email_with_headers("a@shop.com", "not an address")

    assert check_reply_to_mismatch(email) == []
