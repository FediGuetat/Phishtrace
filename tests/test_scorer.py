from pathlib import Path

from phishtrace.parser import parse_email
from phishtrace.rules import Finding, Severity, run_all_rules
from phishtrace.scorer import risk_level, score

FIXTURES = Path(__file__).parent / "fixtures"


def _finding(name, severity):
    return Finding(name, severity, "")


def test_no_findings_is_zero():
    assert score([]) == 0
    assert risk_level(0) == "low"


def test_one_low_finding():
    assert score([_finding("urgency_language", Severity.LOW)]) == 10


def test_one_high_finding_is_only_medium():
    points = score([_finding("link_mismatch", Severity.HIGH)])

    assert points == 40
    assert risk_level(points) == "medium"


def test_two_different_rules_add_up_to_high():
    points = score(
        [
            _finding("link_mismatch", Severity.HIGH),
            _finding("reply_to_mismatch", Severity.MEDIUM),
        ]
    )

    assert points == 60
    assert risk_level(points) == "high"


def test_same_rule_twice_counts_once():
    findings = [
        _finding("link_mismatch", Severity.HIGH),
        _finding("link_mismatch", Severity.HIGH),
    ]

    assert score(findings) == 40


def test_same_rule_keeps_its_worst_severity():
    findings = [
        _finding("suspicious_url", Severity.MEDIUM),
        _finding("suspicious_url", Severity.HIGH),
    ]

    assert score(findings) == 40


def test_score_is_capped_at_100():
    findings = [
        _finding("link_mismatch", Severity.HIGH),
        _finding("brand_impersonation", Severity.HIGH),
        _finding("lookalike_domain", Severity.HIGH),
    ]

    assert score(findings) == 100


def test_level_borders():
    assert risk_level(24) == "low"
    assert risk_level(25) == "medium"
    assert risk_level(59) == "medium"
    assert risk_level(60) == "high"


def test_fake_paypal_email_is_high_risk():
    email = parse_email((FIXTURES / "simple.eml").read_bytes())

    assert risk_level(score(run_all_rules(email))) == "high"
