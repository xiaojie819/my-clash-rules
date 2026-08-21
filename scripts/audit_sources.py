from collections import Counter
from pathlib import Path

import yaml

from compiler.config import enabled_groups, enabled_sources, load_config
from compiler.fetcher import fetch_url_text
from compiler.models import RuleSource, SourceFormat
from compiler.normalize import normalize_rules
from compiler.optimize import optimize_rules
from compiler.parsers import parse_rules
from compiler.sanitize import sanitize_text


def type_counts(rules):
    return Counter(rule.type.value for rule in rules)


def print_counts(title, rules):
    counts = type_counts(rules)

    print(f"\n{title}: {len(rules)}")

    for rule_type, count in sorted(counts.items()):
        print(f"  {rule_type}: {count}")


def audit_group(group):
    print()
    print("=" * 60)
    print(f"GROUP: {group.name}")
    print("=" * 60)

    merged_rules = []
    all_issues = []

    for source in enabled_sources(group):
        print()
        print(f"SOURCE: {source.name}")
        print(f"URL: {source.url}")

        text = fetch_url_text(
            source.url,
            timeout=source.timeout or group.timeout,
        )

        sanitize_result = sanitize_text(text)

        print(
            "sanitize removed:",
            sanitize_result.stats.removed_count,
        )

        rule_source = RuleSource(
            name=source.name,
            url=source.url,
        )

        parsed = parse_rules(
            sanitize_result.text,
            source=rule_source,
            format_hint=source.format,
        )

        print(
            "detected format:",
            parsed.detected_format.value,
        )

        print_counts(
            "parsed rules",
            parsed.rules,
        )

        print(
            "parse issues:",
            len(parsed.issues),
        )

        normalized, normalize_issues = normalize_rules(
            parsed.rules
        )

        print_counts(
            "normalized rules",
            normalized,
        )

        print(
            "normalize issues:",
            len(normalize_issues),
        )

        merged_rules.extend(normalized)
        all_issues.extend(parsed.issues)
        all_issues.extend(normalize_issues)

    print_counts(
        "merged before optimize",
        merged_rules,
    )

    optimized = optimize_rules(
        merged_rules,
        mode=group.optimize_mode,
        sort_output=group.sort_output,
    )

    print_counts(
        "optimized final",
        optimized.rules,
    )

    print(
        "optimize issues:",
        len(optimized.issues),
    )

    output_path = Path(group.output)

    if not output_path.exists():
        print(
            "\nOUTPUT: MISSING",
            output_path,
        )
        return

    data = yaml.safe_load(
        output_path.read_text(
            encoding="utf-8"
        )
    )

    payload = data.get(
        "payload",
        [],
    )

    print()
    print(
        "generated payload:",
        len(payload),
    )

    output_parsed = parse_rules(
        output_path.read_text(
            encoding="utf-8"
        ),
        format_hint=SourceFormat.CLASH_CLASSICAL,
    )

    expected_keys = {
        rule.canonical_key()
        for rule in optimized.rules
    }

    output_keys = {
        rule.canonical_key()
        for rule in output_parsed.rules
    }

    missing = expected_keys - output_keys
    extra = output_keys - expected_keys

    print(
        "missing after render:",
        len(missing),
    )

    print(
        "extra after render:",
        len(extra),
    )

    total_issues = (
        all_issues
        + optimized.issues
        + output_parsed.issues
    )

    print(
        "total issues:",
        len(total_issues),
    )

    if missing:
        print("\nMISSING RULES:")
        for item in sorted(missing):
            print(" ", item)

    if extra:
        print("\nEXTRA RULES:")
        for item in sorted(extra):
            print(" ", item)

    if total_issues:
        print("\nISSUES:")
        for issue in total_issues:
            print(
                f" [{issue.level}] "
                f"{issue.message}"
            )

    assert payload
    assert not missing
    assert not extra

    print()
    print(
        f"RESULT: {group.name} PASS"
    )


def main():
    config = load_config()

    groups = enabled_groups(config)

    if not groups:
        raise SystemExit(
            "没有启用的规则组"
        )

    for group in groups:
        audit_group(group)


if __name__ == "__main__":
    main()
