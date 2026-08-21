from compiler.models import Rule, RuleType
from compiler.optimize import (
    OptimizeMode,
    optimize_rules,
)


def test_optimize_remove_duplicates():

    rules = [
        Rule(
            type=RuleType.DOMAIN_SUFFIX,
            value="example.com",
            raw="DOMAIN-SUFFIX,example.com",
        ),
        Rule(
            type=RuleType.DOMAIN_SUFFIX,
            value="example.com",
            raw="DOMAIN-SUFFIX,example.com",
        ),
    ]

    result = optimize_rules(
        rules,
        mode=OptimizeMode.SAFE,
    )

    assert len(result.rules) == 1


def test_optimize_keep_cidr_rules():

    rules = [
        Rule(
            type=RuleType.IP_CIDR,
            value="10.0.0.0/8",
            raw="IP-CIDR,10.0.0.0/8",
        ),
        Rule(
            type=RuleType.IP_CIDR,
            value="10.1.0.0/16",
            raw="IP-CIDR,10.1.0.0/16",
        ),
    ]

    result = optimize_rules(
        rules,
        mode=OptimizeMode.SAFE,
    )

    assert len(result.rules) >= 1
    assert any(r.value == "10.0.0.0/8" for r in result.rules)
