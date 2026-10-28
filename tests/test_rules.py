from pathlib import Path

from phishtrace.parser import parse_email
from phishtrace.rules import (
    Finding,
    Severity,
    check_brand_impersonation,
    check_link_mismatch,
    check_lookalike_domain,
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


def _email_from(sender):
    return parse_email(f"From: {sender}\n\nHi".encode())


def test_brand_from_wrong_domain_is_flagged():
    email = parse_email((FIXTURES / "simple.eml").read_bytes())

    detail = "display name says paypal but mail comes from paypa1-security.com"
    assert check_brand_impersonation(email) == [
        Finding("brand_impersonation", Severity.HIGH, detail)
    ]


def test_brand_from_real_subdomain_is_fine():
    email = _email_from("Microsoft <noreply@accountprotection.microsoft.com>")

    assert check_brand_impersonation(email) == []


def test_brand_from_other_official_domain_is_fine():
    email = _email_from("Facebook <notification@facebookmail.com>")

    assert check_brand_impersonation(email) == []


def test_brand_from_free_mail_is_flagged():
    email = _email_from("Google Security <google.alerts@gmail.com>")

    assert len(check_brand_impersonation(email)) == 1


def test_brand_match_ignores_case():
    email = _email_from("PAYPAL <x@evil.ru>")

    assert len(check_brand_impersonation(email)) == 1


def test_brand_inside_other_word_is_ignored():
    email = _email_from("Metadata Team <team@example.com>")

    assert check_brand_impersonation(email) == []


def test_no_display_name_is_skipped():
    email = _email_from("paypal@evil.ru")

    assert check_brand_impersonation(email) == []


def test_digit_swapped_domain_is_flagged_once():
    email = parse_email((FIXTURES / "simple.eml").read_bytes())

    detail = "paypa1-security.com looks like paypal"
    assert check_lookalike_domain(email) == [
        Finding("lookalike_domain", Severity.HIGH, detail)
    ]


def test_zero_for_o_is_flagged():
    email = parse_email((FIXTURES / "multipart.eml").read_bytes())

    detail = check_lookalike_domain(email)[0].detail
    assert detail == "micros0ft-support.com looks like microsoft"


def test_rn_for_m_is_flagged():
    email = _email_from("Support <help@rnicrosoft.com>")

    assert len(check_lookalike_domain(email)) == 1


def test_punycode_link_is_flagged():
    email = _email_with_link("Login", "https://xn--pypal-4ve.com/login")

    detail = check_lookalike_domain(email)[0].detail
    assert detail == "xn--pypal-4ve.com uses punycode which can hide lookalike letters"


def test_official_domain_with_digits_is_fine():
    email = _email_from("Amazon <ship@web1.amazon.com>")

    assert check_lookalike_domain(email) == []


def test_normal_domain_with_rn_is_fine():
    email = _email_from("News <news@learnmore.com>")

    assert check_lookalike_domain(email) == []
