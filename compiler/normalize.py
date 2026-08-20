from __future__ import annotations

import ipaddress
import re
from dataclasses import replace

from .models import (
    ParseIssue,
    Rule,
    RuleType,
)

# ============================================================
# 常量
# ============================================================

DOMAIN_TYPES = {
    RuleType.DOMAIN,
    RuleType.DOMAIN_SUFFIX,
    RuleType.DOMAIN_KEYWORD,
}

IP_TYPES = {
    RuleType.IP_CIDR,
    RuleType.IP_CIDR6,
    RuleType.SRC_IP_CIDR,
    RuleType.SRC_IP_CIDR6,
}

PORT_TYPES = {
    RuleType.DST_PORT,
    RuleType.SRC_PORT,
}


# ============================================================
# 基础工具
# ============================================================

def _clean_string(value: str) -> str:
    """
    基础字符串清理：
    - 去首尾空格
    - 去最外层引号
    """
    value = value.strip()

    if len(value) >= 2 and (
        (
            value.startswith('"')
            and value.endswith('"')
        ) or (
            value.startswith("'")
            and value.endswith("'")
        )
    ):
            value = value[1:-1].strip()

    return value


def _normalize_options(options: list[str]) -> list[str]:
    """
    统一 options：
    - 去空值
    - trim
    - 小写
    - 去重
    - 保序
    """
    output: list[str] = []

    seen: set[str] = set()

    for item in options:
        item = _clean_string(item)

        if not item:
            continue

        normalized = item.lower()

        if normalized in seen:
            continue

        seen.add(normalized)
        output.append(normalized)

    return output


def _clone_rule(
    rule: Rule,
    **changes,
) -> Rule:
    """
    dataclass slots=True 下，
    使用 replace 创建新对象。

    不原地乱改，便于后续排错。
    """
    return replace(
        rule,
        **changes,
    )


# ============================================================
# 域名规范化
# ============================================================

def normalize_domain_value(
    value: str,
    rule_type: RuleType,
) -> tuple[str | None, str | None]:
    """
    返回：
        (normalized_value, error)

    DOMAIN / DOMAIN-SUFFIX:
        Example.COM.
        -> example.com

    DOMAIN-KEYWORD:
        保留关键词语义，只做 trim/lower。
    """

    value = _clean_string(value)

    if not value:
        return None, "域名规则 value 为空"

    # DOMAIN-KEYWORD 不是完整域名
    if rule_type == RuleType.DOMAIN_KEYWORD:
        value = value.lower()

        if not value:
            return None, "DOMAIN-KEYWORD 为空"

        return value, None

    # 防止上游把 domain provider 风格残留进来
    value = value.removeprefix("+.")

    value = value.removeprefix("*.")

    value = value.strip().lower()

    # DNS FQDN 尾点统一去掉
    value = value.rstrip(".")

    if not value:
        return None, "域名清理后为空"

    # 不允许 URL
    if "://" in value:
        return None, "域名规则中出现 URL"

    # 不允许路径
    if "/" in value:
        return None, "域名规则中出现路径"

    # 不允许逗号
    if "," in value:
        return None, "域名规则中出现逗号"

    # 比较宽松的域名校验
    # 允许：
    #   xn--...
    #   下划线
    #   数字
    pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:"
        r"[a-z0-9_]"
        r"(?:[a-z0-9_-]{0,61}[a-z0-9_])?"
        r"\."
        r")+"
        r"[a-z0-9]"
        r"(?:[a-z0-9-]{0,61}[a-z0-9])?"
        r"$"
    )

    # DOMAIN 可能有 localhost / router 等单标签名称
    if rule_type == RuleType.DOMAIN and "." not in value:
            single_label = re.compile(
                r"^[a-z0-9_][a-z0-9_-]{0,62}$"
            )

            if not single_label.match(value):
                return None, "DOMAIN 单标签格式无效"

            return value, None

    if not pattern.match(value):

        # Clash/Mihomo 允许本地域名：
        # local
        # lan
        # internal
        # localhost
        # home

        single_label = re.compile(
            r"^[a-z0-9_][a-z0-9_-]{0,62}$"
        )

        if single_label.match(value):
            return value, None

        return None, "域名格式无效"

    return value, None


# ============================================================
# IP / CIDR 规范化
# ============================================================

def normalize_cidr_value(
    value: str,
    rule_type: RuleType,
) -> tuple[str | None, RuleType, str | None]:
    """
    CIDR 网络化。

    例如：
        192.168.1.5/24
        -> 192.168.1.0/24

        2001:db8::1/64
        -> 2001:db8::/64

    同时自动修正 IP-CIDR / IP-CIDR6 类型。
    """

    value = _clean_string(value)

    if not value:
        return None, rule_type, "CIDR value 为空"

    try:
        network = ipaddress.ip_network(
            value,
            strict=False,
        )

    except ValueError:
        return None, rule_type, "无效 CIDR"

    normalized = str(network)

    if network.version == 4:
        if rule_type == RuleType.SRC_IP_CIDR6:
            new_type = RuleType.SRC_IP_CIDR
        elif rule_type == RuleType.IP_CIDR6:
            new_type = RuleType.IP_CIDR
        else:
            new_type = rule_type

    else:
        if rule_type == RuleType.SRC_IP_CIDR:
            new_type = RuleType.SRC_IP_CIDR6
        elif rule_type == RuleType.IP_CIDR:
            new_type = RuleType.IP_CIDR6
        else:
            new_type = rule_type

    return normalized, new_type, None


# ============================================================
# 端口规范化
# ============================================================

def normalize_port_value(
    value: str,
) -> tuple[str | None, str | None]:
    """
    支持：
        80
        443
        1000-2000

    暂不支持复杂集合：
        80,443
        80/443
    """
    value = _clean_string(value)

    if not value:
        return None, "端口 value 为空"

    if value.isdigit():
        port = int(value)

        if 1 <= port <= 65535:
            return str(port), None

        return None, "端口超出 1-65535"

    match = re.fullmatch(
        r"(\d+)-(\d+)",
        value,
    )

    if match:
        start = int(match.group(1))
        end = int(match.group(2))

        if not (
            1 <= start <= 65535
            and 1 <= end <= 65535
        ):
            return None, "端口范围超出 1-65535"

        if start > end:
            start, end = end, start

        return f"{start}-{end}", None

    return None, "端口格式无效"


# ============================================================
# NETWORK
# ============================================================

def normalize_network_value(
    value: str,
) -> tuple[str | None, str | None]:
    value = _clean_string(value).lower()

    aliases = {
        "tcp": "tcp",
        "udp": "udp",
    }

    normalized = aliases.get(value)

    if normalized is None:
        return None, f"未知 NETWORK 类型: {value}"

    return normalized, None


# ============================================================
# GEOIP / GEOSITE
# ============================================================

def normalize_geo_value(
    value: str,
) -> tuple[str | None, str | None]:
    """
    GEOIP / GEOSITE 做保守清理。

    GEOIP:
        CN -> cn

    GEOSITE:
        google
        category-ai-!cn
        保留符号，只转小写。
    """
    value = _clean_string(value).lower()

    if not value:
        return None, "GEO value 为空"

    if any(
        char.isspace()
        for char in value
    ):
        return None, "GEO value 包含空白字符"

    return value, None


# ============================================================
# PROCESS
# ============================================================

def normalize_process_value(
    value: str,
) -> tuple[str | None, str | None]:
    """
    进程名/路径不强行转小写。

    Windows 路径可能不区分大小写，
    Linux/macOS 路径可能区分，
    所以保持原样。
    """
    value = _clean_string(value)

    if not value:
        return None, "PROCESS value 为空"

    return value, None


# ============================================================
# RULE-SET / URL-REGEX / UNKNOWN
# ============================================================

def normalize_generic_value(
    value: str,
) -> tuple[str | None, str | None]:
    value = _clean_string(value)

    if not value:
        return None, "规则 value 为空"

    return value, None


# ============================================================
# 单条规则规范化
# ============================================================

def normalize_rule(
    rule: Rule,
) -> tuple[Rule, list[ParseIssue]]:
    """
    规范化单条 Rule。

    返回：
        normalized_rule
        issues
    """

    issues: list[ParseIssue] = []

    # 已经禁用的规则仍做最基本清理，
    # 但不强制恢复
    enabled = rule.enabled

    value = rule.value

    rule_type = rule.type

    options = _normalize_options(
        rule.options
    )

    tags = set(rule.tags)

    metadata = dict(
        rule.metadata
    )

    # --------------------------------------------------------
    # DOMAIN
    # --------------------------------------------------------

    if rule_type in DOMAIN_TYPES:
        normalized_value, error = normalize_domain_value(
            value,
            rule_type,
        )

        if error:
            enabled = False

            tags.add(
                "normalize-error"
            )

            issues.append(
                ParseIssue(
                    message=error,
                    raw=rule.raw,
                    source=rule.source,
                    level="warning",
                )
            )

        else:
            value = normalized_value or value

    # --------------------------------------------------------
    # IP
    # --------------------------------------------------------

    elif rule_type in IP_TYPES:
        (
            normalized_value,
            corrected_type,
            error,
        ) = normalize_cidr_value(
            value,
            rule_type,
        )

        if error:
            enabled = False

            tags.add(
                "normalize-error"
            )

            issues.append(
                ParseIssue(
                    message=error,
                    raw=rule.raw,
                    source=rule.source,
                    level="warning",
                )
            )

        else:
            value = normalized_value or value

            if corrected_type != rule_type:
                metadata[
                    "original_rule_type"
                ] = rule_type.value

                tags.add(
                    "type-corrected"
                )

                rule_type = corrected_type

        # IP 规则统一 no-resolve
        if "no-resolve" not in options:
            options.append(
                "no-resolve"
            )

    # --------------------------------------------------------
    # PORT
    # --------------------------------------------------------

    elif rule_type in PORT_TYPES:
        normalized_value, error = normalize_port_value(
            value
        )

        if error:
            enabled = False

            tags.add(
                "normalize-error"
            )

            issues.append(
                ParseIssue(
                    message=error,
                    raw=rule.raw,
                    source=rule.source,
                    level="warning",
                )
            )

        else:
            value = normalized_value or value

    # --------------------------------------------------------
    # NETWORK
    # --------------------------------------------------------

    elif rule_type == RuleType.NETWORK:
        normalized_value, error = normalize_network_value(
            value
        )

        if error:
            enabled = False

            tags.add(
                "normalize-error"
            )

            issues.append(
                ParseIssue(
                    message=error,
                    raw=rule.raw,
                    source=rule.source,
                    level="warning",
                )
            )

        else:
            value = normalized_value or value

    # --------------------------------------------------------
    # GEO
    # --------------------------------------------------------

    elif rule_type in {
        RuleType.GEOIP,
        RuleType.GEOSITE,
    }:
        normalized_value, error = normalize_geo_value(
            value
        )

        if error:
            enabled = False

            tags.add(
                "normalize-error"
            )

            issues.append(
                ParseIssue(
                    message=error,
                    raw=rule.raw,
                    source=rule.source,
                    level="warning",
                )
            )

        else:
            value = normalized_value or value

    # --------------------------------------------------------
    # PROCESS
    # --------------------------------------------------------

    elif rule_type in {
        RuleType.PROCESS_NAME,
        RuleType.PROCESS_PATH,
    }:
        normalized_value, error = normalize_process_value(
            value
        )

        if error:
            enabled = False

            tags.add(
                "normalize-error"
            )

            issues.append(
                ParseIssue(
                    message=error,
                    raw=rule.raw,
                    source=rule.source,
                    level="warning",
                )
            )

        else:
            value = normalized_value or value

    # --------------------------------------------------------
    # GENERIC
    # --------------------------------------------------------

    else:
        normalized_value, error = normalize_generic_value(
            value
        )

        if error:
            enabled = False

            tags.add(
                "normalize-error"
            )

            issues.append(
                ParseIssue(
                    message=error,
                    raw=rule.raw,
                    source=rule.source,
                    level="warning",
                )
            )

        else:
            value = normalized_value or value

    normalized_rule = _clone_rule(
        rule,
        type=rule_type,
        value=value,
        options=options,
        enabled=enabled,
        tags=tags,
        metadata=metadata,
    )

    return normalized_rule, issues


# ============================================================
# 批量规范化
# ============================================================

def normalize_rules(
    rules: list[Rule],
) -> tuple[list[Rule], list[ParseIssue]]:
    """
    批量规范化。
    """

    normalized_rules: list[Rule] = []

    issues: list[ParseIssue] = []

    for rule in rules:
        normalized, rule_issues = normalize_rule(
            rule
        )

        normalized_rules.append(
            normalized
        )

        issues.extend(
            rule_issues
        )

    return normalized_rules, issues


# ============================================================
# 调试辅助
# ============================================================

def normalization_summary(
    rules: list[Rule],
) -> dict[str, int]:
    """
    给后续 report 使用的简单统计。
    """

    total = len(rules)

    enabled = sum(
        1
        for rule in rules
        if rule.enabled
    )

    disabled = total - enabled

    corrected = sum(
        1
        for rule in rules
        if "type-corrected" in rule.tags
    )

    errors = sum(
        1
        for rule in rules
        if "normalize-error" in rule.tags
    )

    return {
        "total": total,
        "enabled": enabled,
        "disabled": disabled,
        "type_corrected": corrected,
        "normalize_errors": errors,
    }
