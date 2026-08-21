from compiler.models import Rule, RuleType
from compiler.normalize import normalize_rules


def test_normalize_domain_rule():

    rules = [
        Rule(
            type=RuleType.DOMAIN_SUFFIX,
            value=" Example.COM ",
            raw="DOMAIN-SUFFIX, Example.COM ",
        )
    ]

    normalized, issues = normalize_rules(rules)

    assert len(issues) == 0
    assert len(normalized) == 1
    assert normalized[0].value == "example.com"


def test_normalize_cidr_rule():

    rules = [
        Rule(
            type=RuleType.IP_CIDR,
            value="192.168.1.0/24",
            raw="IP-CIDR,192.168.1.0/24",
        )
    ]

    normalized, issues = normalize_rules(rules)

    assert len(issues) == 0
    assert normalized[0].value == "192.168.1.0/24"
