from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, replace
from enum import Enum

from .models import (
    BuildStats,
    ParseIssue,
    Rule,
    RuleSource,
    RuleType,
)

# ============================================================
# 优化模式
# ============================================================

class OptimizeMode(str, Enum):
    """
    SAFE:
        只删除完全重复。
        覆盖关系只标记/报告。

    AGGRESSIVE:
        除完全重复外，
        还会删除明确被更宽规则覆盖的规则。
    """

    SAFE = "safe"
    AGGRESSIVE = "aggressive"


# ============================================================
# 优化结果
# ============================================================

@dataclass(slots=True)
class OptimizeResult:
    rules: list[Rule] = field(default_factory=list)

    issues: list[ParseIssue] = field(default_factory=list)

    duplicate_count: int = 0

    covered_domain_count: int = 0

    covered_cidr_count: int = 0

    disabled_count: int = 0

    input_count: int = 0

    output_count: int = 0


# ============================================================
# 通用工具
# ============================================================

def _clone_rule(
    rule: Rule,
    **changes,
) -> Rule:
    return replace(
        rule,
        **changes,
    )


def _source_to_dict(
    source: RuleSource | None,
) -> dict[str, object] | None:
    if source is None:
        return None

    return {
        "name": source.name,
        "url": source.url,
        "file": source.file,
        "format": source.format.value,
        "line_number": source.line_number,
        "metadata": dict(source.metadata),
    }


def _merge_sources_into_metadata(
    keeper: Rule,
    duplicate: Rule,
) -> Rule:
    """
    完全重复规则被去掉时，
    把重复项来源记录到保留规则 metadata 中。

    这样去重后仍知道：
        这条规则来自哪些上游。
    """

    metadata = dict(
        keeper.metadata
    )

    provenance = list(
        metadata.get(
            "provenance",
            [],
        )
    )

    existing_source = _source_to_dict(
        keeper.source
    )

    duplicate_source = _source_to_dict(
        duplicate.source
    )

    if (
        existing_source is not None
        and existing_source not in provenance
    ):
        provenance.append(
            existing_source
        )

    if (
        duplicate_source is not None
        and duplicate_source not in provenance
    ):
        provenance.append(
            duplicate_source
        )

    if provenance:
        metadata[
            "provenance"
        ] = provenance

    tags = set(
        keeper.tags
    )

    tags.add(
        "merged-source"
    )

    return _clone_rule(
        keeper,
        metadata=metadata,
        tags=tags,
    )


# ============================================================
# 完全重复去重
# ============================================================

def deduplicate_exact(
    rules: list[Rule],
) -> tuple[list[Rule], int]:
    """
    按 Rule.canonical_key() 去重。

    normalize.py 跑完以后，
    例如：

        DOMAIN-SUFFIX,Google.com
        DOMAIN-SUFFIX,google.com

    已经会拥有同一个 canonical key。
    """

    output: list[Rule] = []

    key_to_index: dict[
        tuple[str, str, tuple[str, ...]],
        int,
    ] = {}

    duplicate_count = 0

    for rule in rules:

        # 禁用规则不参与正常 dedupe，
        # 避免 UNKNOWN / 无效规则信息被吃掉。
        if not rule.enabled:
            output.append(
                rule
            )
            continue

        key = rule.canonical_key()

        existing_index = key_to_index.get(
            key
        )

        if existing_index is None:
            key_to_index[
                key
            ] = len(output)

            output.append(
                rule
            )
            continue

        duplicate_count += 1

        existing_rule = output[
            existing_index
        ]

        output[
            existing_index
        ] = _merge_sources_into_metadata(
            existing_rule,
            rule,
        )

    return output, duplicate_count


# ============================================================
# DOMAIN 覆盖分析
# ============================================================

def _domain_is_under_suffix(
    domain: str,
    suffix: str,
) -> bool:
    """
    判断：

        api.example.com
        是否被
        example.com

    覆盖。
    """

    domain = domain.lower().rstrip(
        "."
    )

    suffix = suffix.lower().rstrip(
        "."
    )

    if domain == suffix:
        return True

    return domain.endswith(
        "." + suffix
    )


def analyze_domain_coverage(
    rules: list[Rule],
    *,
    aggressive: bool = False,
) -> tuple[
    list[Rule],
    int,
    list[ParseIssue],
]:
    """
    DOMAIN-SUFFIX 可以覆盖：

        DOMAIN,example.com
        DOMAIN,api.example.com

    但默认 SAFE 模式不删，
    只加：
        covered-by-domain-suffix

    AGGRESSIVE 模式才会真正移除被覆盖 DOMAIN。
    """

    suffixes = {
        rule.value
        for rule in rules
        if (
            rule.enabled
            and rule.type
            == RuleType.DOMAIN_SUFFIX
        )
    }

    if not suffixes:
        return rules, 0, []

    issues: list[ParseIssue] = []

    output: list[Rule] = []

    covered_count = 0

    # 长 suffix 优先没有特别必要，
    # 但后面报告时更容易找到最具体覆盖项。
    sorted_suffixes = sorted(
        suffixes,
        key=len,
        reverse=True,
    )

    for rule in rules:

        if (
            not rule.enabled
            or rule.type != RuleType.DOMAIN
        ):
            output.append(
                rule
            )
            continue

        covering_suffix: str | None = None

        for suffix in sorted_suffixes:
            if _domain_is_under_suffix(
                rule.value,
                suffix,
            ):
                covering_suffix = suffix
                break

        if covering_suffix is None:
            output.append(
                rule
            )
            continue

        covered_count += 1

        issues.append(
            ParseIssue(
                message=(
                    f"DOMAIN {rule.value} "
                    f"被 DOMAIN-SUFFIX "
                    f"{covering_suffix} 覆盖"
                ),
                raw=rule.raw,
                source=rule.source,
                level="info",
            )
        )

        if aggressive:
            continue

        tags = set(
            rule.tags
        )

        tags.add(
            "covered-by-domain-suffix"
        )

        metadata = dict(
            rule.metadata
        )

        metadata[
            "covered_by"
        ] = {
            "type": RuleType.DOMAIN_SUFFIX.value,
            "value": covering_suffix,
        }

        output.append(
            _clone_rule(
                rule,
                tags=tags,
                metadata=metadata,
            )
        )

    return (
        output,
        covered_count,
        issues,
    )


# ============================================================
# CIDR 覆盖分析
# ============================================================

def _parse_network(
    rule: Rule,
) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(
            rule.value,
            strict=False,
        )

    except ValueError:
        return None


def analyze_cidr_coverage(
    rules: list[Rule],
    *,
    aggressive: bool = False,
) -> tuple[
    list[Rule],
    int,
    list[ParseIssue],
]:
    """
    检测同类 CIDR：

        1.2.3.0/24
        1.2.3.4/32

    后者被前者覆盖。

    IPv4 / IPv6 分开处理。
    SRC-IP-CIDR 也不会和 IP-CIDR 相互覆盖，
    因为语义不同。
    """

    cidr_types = {
        RuleType.IP_CIDR,
        RuleType.IP_CIDR6,
        RuleType.SRC_IP_CIDR,
        RuleType.SRC_IP_CIDR6,
    }

    by_type: dict[
        RuleType,
        list[
            tuple[
                Rule,
                ipaddress._BaseNetwork,
            ]
        ],
    ] = {}

    for rule in rules:
        if (
            not rule.enabled
            or rule.type not in cidr_types
        ):
            continue

        network = _parse_network(
            rule
        )

        if network is None:
            continue

        by_type.setdefault(
            rule.type,
            [],
        ).append(
            (
                rule,
                network,
            )
        )

    coverage_map: dict[
        tuple[str, str, tuple[str, ...]],
        Rule,
    ] = {}

    for items in by_type.values():

        # prefixlen 越小，网段越大。
        sorted_items = sorted(
            items,
            key=lambda item: (
                item[1].version,
                item[1].prefixlen,
                int(
                    item[1].network_address
                ),
            ),
        )

        accepted: list[
            tuple[
                Rule,
                ipaddress._BaseNetwork,
            ]
        ] = []

        for rule, network in sorted_items:

            covering_rule: Rule | None = None

            for parent_rule, parent_network in accepted:

                if (
                    parent_network.version
                    != network.version
                ):
                    continue

                if network.subnet_of(
                    parent_network
                ):
                    covering_rule = parent_rule
                    break

            if covering_rule is not None:
                coverage_map[
                    rule.canonical_key()
                ] = covering_rule
                continue

            accepted.append(
                (
                    rule,
                    network,
                )
            )

    if not coverage_map:
        return rules, 0, []

    output: list[Rule] = []

    issues: list[ParseIssue] = []

    covered_count = 0

    for rule in rules:

        covering_rule = coverage_map.get(
            rule.canonical_key()
        )

        if covering_rule is None:
            output.append(
                rule
            )
            continue

        covered_count += 1

        # CIDR 覆盖属于集合关系，
        # 但在 Clash 规则中保留小网段
        # 有时是为了可读性和兼容性。
        #
        # SAFE 模式：
        # 不删除、不产生提示。
        #
        # AGGRESSIVE 模式：
        # 后续才考虑真正移除。

        if aggressive:
            continue

        tags = set(
            rule.tags
        )

        tags.add(
            "covered-by-cidr"
        )

        metadata = dict(
            rule.metadata
        )

        metadata[
            "covered_by"
        ] = {
            "type": covering_rule.type.value,
            "value": covering_rule.value,
        }

        output.append(
            _clone_rule(
                rule,
                tags=tags,
                metadata=metadata,
            )
        )

    return (
        output,
        covered_count,
        issues,
    )


# ============================================================
# 跨类型潜在冲突分析
# ============================================================

def analyze_rule_conflicts(
    rules: list[Rule],
) -> list[ParseIssue]:
    """
    这里只报告一些值得人工关注的情况。

    不自动修改。
    """

    issues: list[ParseIssue] = []

    domain_exact = {
        rule.value
        for rule in rules
        if (
            rule.enabled
            and rule.type == RuleType.DOMAIN
        )
    }

    domain_suffix = {
        rule.value
        for rule in rules
        if (
            rule.enabled
            and rule.type
            == RuleType.DOMAIN_SUFFIX
        )
    }

    domain_keywords = {
        rule.value
        for rule in rules
        if (
            rule.enabled
            and rule.type
            == RuleType.DOMAIN_KEYWORD
        )
    }

    # 同一个值同时 exact 和 suffix
    for value in sorted(
        domain_exact
        & domain_suffix
    ):
        issues.append(
            ParseIssue(
                message=(
                    f"{value} 同时存在 "
                    "DOMAIN 与 DOMAIN-SUFFIX"
                ),
                level="info",
            )
        )

    # keyword 太短，潜在误伤
    for keyword in sorted(
        domain_keywords
    ):
        if len(keyword) <= 2:
            issues.append(
                ParseIssue(
                    message=(
                        "DOMAIN-KEYWORD "
                        f"{keyword!r} 过短，"
                        "可能产生大范围误匹配"
                    ),
                    level="warning",
                )
            )

    return issues


# ============================================================
# 排序
# ============================================================

RULE_TYPE_ORDER: dict[
    RuleType,
    int,
] = {
    RuleType.DOMAIN: 10,
    RuleType.DOMAIN_SUFFIX: 20,
    RuleType.DOMAIN_KEYWORD: 30,

    RuleType.IP_CIDR: 40,
    RuleType.IP_CIDR6: 50,

    RuleType.SRC_IP_CIDR: 60,
    RuleType.SRC_IP_CIDR6: 70,

    RuleType.PROCESS_NAME: 80,
    RuleType.PROCESS_PATH: 90,

    RuleType.DST_PORT: 100,
    RuleType.SRC_PORT: 110,

    RuleType.NETWORK: 120,

    RuleType.GEOIP: 130,
    RuleType.GEOSITE: 140,

    RuleType.RULE_SET: 150,

    RuleType.URL_REGEX: 160,

    RuleType.UNKNOWN: 999,
}


def sort_rules(
    rules: list[Rule],
) -> list[Rule]:
    """
    只为了输出稳定、方便 diff。

    不代表运行优先级，
    因为这些规则最终属于同一个 rule-provider。
    """

    def key(
        rule: Rule,
    ) -> tuple[
        int,
        str,
        str,
    ]:
        return (
            RULE_TYPE_ORDER.get(
                rule.type,
                900,
            ),
            rule.value.lower(),
            ",".join(
                rule.options
            ),
        )

    return sorted(
        rules,
        key=key,
    )


# ============================================================
# 主优化流程
# ============================================================

def optimize_rules(
    rules: list[Rule],
    *,
    mode: OptimizeMode = OptimizeMode.SAFE,
    sort_output: bool = True,
) -> OptimizeResult:
    """
    主入口。

    推荐默认：
        SAFE
    """

    result = OptimizeResult(
        input_count=len(rules)
    )

    # --------------------------------------------------------
    # 1. 完全重复
    # --------------------------------------------------------

    deduped, duplicate_count = deduplicate_exact(
        rules
    )

    result.duplicate_count = (
        duplicate_count
    )

    # --------------------------------------------------------
    # 2. DOMAIN 覆盖
    # --------------------------------------------------------

    aggressive = (
        mode == OptimizeMode.AGGRESSIVE
    )

    (
        domain_processed,
        domain_covered_count,
        domain_issues,
    ) = analyze_domain_coverage(
        deduped,
        aggressive=aggressive,
    )

    result.covered_domain_count = (
        domain_covered_count
    )

    result.issues.extend(
        domain_issues
    )

    # --------------------------------------------------------
    # 3. CIDR 覆盖
    # --------------------------------------------------------

    (
        cidr_processed,
        cidr_covered_count,
        cidr_issues,
    ) = analyze_cidr_coverage(
        domain_processed,
        aggressive=aggressive,
    )

    result.covered_cidr_count = (
        cidr_covered_count
    )

    result.issues.extend(
        cidr_issues
    )

    # --------------------------------------------------------
    # 4. 冲突分析
    # --------------------------------------------------------

    result.issues.extend(
        analyze_rule_conflicts(
            cidr_processed
        )
    )

    # --------------------------------------------------------
    # 5. disabled 统计
    # --------------------------------------------------------

    result.disabled_count = sum(
        1
        for rule in cidr_processed
        if not rule.enabled
    )

    # --------------------------------------------------------
    # 6. 排序
    # --------------------------------------------------------

    final_rules = (
        sort_rules(
            cidr_processed
        )
        if sort_output
        else list(
            cidr_processed
        )
    )

    result.rules = final_rules

    result.output_count = len(
        final_rules
    )

    return result


# ============================================================
# BuildStats 集成
# ============================================================

def apply_optimize_stats(
    stats: BuildStats,
    result: OptimizeResult,
) -> BuildStats:
    """
    把 OptimizeResult 写入 BuildStats。
    """

    stats.duplicate_count += (
        result.duplicate_count
    )

    stats.covered_rule_count += (
        result.covered_domain_count
        + result.covered_cidr_count
    )

    stats.final_rule_count = (
        result.output_count
    )

    stats.issues.extend(
        issue.message
        for issue in result.issues
    )

    return stats


# ============================================================
# 调试摘要
# ============================================================

def optimization_summary(
    result: OptimizeResult,
) -> dict[str, int]:
    return {
        "input_count": result.input_count,
        "output_count": result.output_count,
        "duplicate_count": result.duplicate_count,
        "covered_domain_count": (
            result.covered_domain_count
        ),
        "covered_cidr_count": (
            result.covered_cidr_count
        ),
        "disabled_count": result.disabled_count,
        "issue_count": len(
            result.issues
        ),
    }
