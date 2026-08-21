from compiler.models import RuleSource, RuleType, SourceFormat
from compiler.extractor import extract_rules


def test_parse_classical_rules():
    text = """
payload:
  - "DOMAIN-SUFFIX,example.com"
  - "IP-CIDR,192.168.1.0/24,no-resolve"
"""

    result = extract_rules(
        text,
        RuleSource(name="test"),
        format_hint=SourceFormat.CLASH_CLASSICAL,
    )

    assert len(result.rules) == 2

    assert result.rules[0].type == RuleType.DOMAIN_SUFFIX
    assert result.rules[0].value == "example.com"

    assert result.rules[1].type == RuleType.IP_CIDR
    assert result.rules[1].value == "192.168.1.0/24"
