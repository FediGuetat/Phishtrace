from phishtrace.rules import Finding, Severity

# guesses for now step 3 tunes them with real data
POINTS = {Severity.HIGH: 40, Severity.MEDIUM: 20, Severity.LOW: 10}


def score(findings: list[Finding]) -> int:
    # three bad links are one trick not three so each rule counts once
    worst = {}
    for finding in findings:
        worst[finding.name] = max(finding.severity, worst.get(finding.name, 0))
    return min(100, sum(POINTS[severity] for severity in worst.values()))


def risk_level(points: int) -> str:
    # one strong sign alone is only medium it takes two to say high
    if points >= 60:
        return "high"
    if points >= 25:
        return "medium"
    return "low"
