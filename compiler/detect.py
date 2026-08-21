from __future__ import annotations

import ipaddress
import json
import re
from collections.abc import Iterable
from dataclasses import dataclass

from .models import SourceFormat

# ============================================================
# 常见规则类型
# ============================================================

RULE_TYPES = {
    "DOMAIN",
    "DOMAIN-SUFFIX",
    "DOMAIN-KEYWORD",
    "DOMAIN-WILDCARD",
    "DOMAIN-REGEX",
    "IP-CIDR",
    "IP-CIDR6",
    "SRC-IP-CIDR",
    "SRC-IP-CIDR6",
    "PROCESS-NAME",
    "PROCESS-PATH",
    "DST-PORT",
    "SRC-PORT",
    "NETWORK",
    "GEOIP",
    "GEOSITE",
    "RULE-SET",
    "RULESET",
    "URL-REGEX",
    "AND",
    "OR",
    "NOT",
    "MATCH",
    "FINAL",
}


COMMENT_PREFIXES = (
    "#",
    "//",
    ";",
)


@dataclass(slots=True)
class DetectionResult:
    """
    格式检测结果。
    """

    format: SourceFormat

    # 0.0 ~ 1.0
    confidence: float

    # 给报告/调试看的原因
    reason: str

    # 检测到的一些特征
    features: dict[str, int | bool | str]


# ============================================================
# 基础文本工具
# ============================================================


def normalize_text(text: str) -> str:
    """
    统一换行、去 BOM。
    """
    if not text:
        return ""

    text = text.lstrip("\ufeff")

    return text.replace("\r\n", "\n").replace("\r", "\n")


def iter_meaningful_lines(text: str) -> Iterable[str]:
    """
    返回用于检测的有效行：
    - 去空行
    - 去纯注释行
    """
    for raw_line in normalize_text(text).split("\n"):
        line = raw_line.strip()

        if not line:
            continue

        if line.startswith(COMMENT_PREFIXES):
            continue

        yield line


def strip_yaml_list_prefix(line: str) -> str:
    """
    classical YAML 经常是：

        - DOMAIN-SUFFIX,example.com

    去掉最前面的 "- "。
    """
    line = line.strip()

    if line.startswith("- "):
        return line[2:].strip()

    return line


def strip_quotes(value: str) -> str:
    """
    去除最外层单/双引号。
    """
    value = value.strip()

    if len(value) >= 2:
        if value.startswith('"') and value.endswith('"'):
            return value[1:-1].strip()

        if value.startswith("'") and value.endswith("'"):
            return value[1:-1].strip()

    return value


# ============================================================
# 单行类型识别
# ============================================================


def looks_like_classical_rule(line: str) -> bool:
    """
    判断是否像：

        DOMAIN-SUFFIX,example.com
        IP-CIDR,1.2.3.0/24,no-resolve
        PROCESS-NAME,chrome.exe
    """
    line = strip_quotes(strip_yaml_list_prefix(line))

    if "," not in line:
        return False

    first = line.split(",", 1)[0].strip().upper()

    return first in RULE_TYPES


def looks_like_domain(value: str) -> bool:
    """
    判断是否像普通域名。

    支持：
        example.com
        sub.example.com
        *.example.com
        +.example.com

    不把 URL 当域名。
    """
    value = strip_quotes(value.strip())

    if not value:
        return False

    # 常见 domain-provider 前缀
    if value.startswith(
        (
            "+.",
            "*.",
        )
    ):
        value = value[2:]

    # 排除 URL
    if "://" in value:
        return False

    # 排除明显规则表达式
    if "," in value:
        return False

    # 排除路径
    if "/" in value:
        return False

    # localhost 等没有点的名字不作为纯 domain 格式强证据
    if "." not in value:
        return False

    # 基本域名校验
    domain_pattern = re.compile(
        r"^(?=.{1,253}$)"
        r"(?:"
        r"[A-Za-z0-9_]"
        r"(?:[A-Za-z0-9_-]{0,61}[A-Za-z0-9_])?"
        r"\."
        r")+"
        r"[A-Za-z0-9]"
        r"(?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        r"\.?$"
    )

    return bool(domain_pattern.match(value))


def looks_like_cidr(value: str) -> bool:
    """
    IPv4 / IPv6 CIDR。
    """
    value = strip_quotes(value.strip())

    if not value:
        return False

    try:
        ipaddress.ip_network(
            value,
            strict=False,
        )
        return "/" in value

    except ValueError:
        return False


def looks_like_ip(value: str) -> bool:
    """
    单个 IPv4 / IPv6 地址。
    """
    value = strip_quotes(value.strip())

    try:
        ipaddress.ip_address(value)
        return True

    except ValueError:
        return False


# ============================================================
# 格式特征
# ============================================================


def has_yaml_payload(text: str) -> bool:
    """
    是否存在 YAML:

        payload:
    """
    for line in normalize_text(text).split("\n"):
        if re.match(
            r"^\s*payload\s*:\s*$",
            line,
            flags=re.IGNORECASE,
        ):
            return True

    return False


def has_yaml_behavior(text: str) -> str | None:
    """
    某些文件可能包含：

        behavior: classical
        behavior: domain
        behavior: ipcidr

    虽然 provider 配置更常见于外部 YAML，
    但检测器顺手支持。
    """
    pattern = re.compile(
        r"^\s*behavior\s*:\s*"
        r"[\"']?"
        r"(classical|domain|ipcidr)"
        r"[\"']?"
        r"\s*$",
        flags=re.IGNORECASE | re.MULTILINE,
    )

    match = pattern.search(normalize_text(text))

    if not match:
        return None

    return match.group(1).lower()


def looks_like_json(text: str) -> bool:
    """
    是否为合法 JSON。
    """
    stripped = normalize_text(text).strip()

    if not stripped:
        return False

    if not stripped.startswith(
        (
            "{",
            "[",
        )
    ):
        return False

    try:
        json.loads(stripped)
        return True

    except json.JSONDecodeError:
        return False


def looks_like_yaml_document(text: str) -> bool:
    """
    这里只做非常轻量的 YAML 特征判断。

    不引入 PyYAML。
    真正 YAML 解析以后放 parsers.py。
    """
    meaningful = list(iter_meaningful_lines(text))

    if not meaningful:
        return False

    yaml_key_count = 0

    for line in meaningful[:50]:
        if re.match(
            r"^[A-Za-z0-9_.-]+\s*:",
            line,
        ):
            yaml_key_count += 1

    return yaml_key_count >= 1


# ============================================================
# 主检测
# ============================================================


def detect_format(text: str) -> DetectionResult:
    """
    自动检测输入规则格式。

    检测优先级非常重要：

    1. JSON
    2. 明确 behavior
    3. payload YAML classical/domain/ipcidr
    4. Surge / Loon / 混合 classical 文本
    5. 纯 CIDR
    6. 纯域名
    7. 普通 YAML
    8. mixed / unknown
    """

    text = normalize_text(text)

    if not text.strip():
        return DetectionResult(
            format=SourceFormat.UNKNOWN,
            confidence=1.0,
            reason="输入为空",
            features={
                "empty": True,
            },
        )

    lines = list(iter_meaningful_lines(text))

    features: dict[str, int | bool | str] = {
        "line_count": len(lines),
        "has_payload": has_yaml_payload(text),
    }

    # --------------------------------------------------------
    # 1. JSON
    # --------------------------------------------------------

    if looks_like_json(text):
        return DetectionResult(
            format=SourceFormat.JSON,
            confidence=0.98,
            reason="内容是合法 JSON 文档",
            features=features,
        )

    # --------------------------------------------------------
    # 2. 显式 behavior
    # --------------------------------------------------------

    behavior = has_yaml_behavior(text)

    if behavior:
        features["behavior"] = behavior

        mapping = {
            "classical": SourceFormat.CLASH_CLASSICAL,
            "domain": SourceFormat.CLASH_DOMAIN,
            "ipcidr": SourceFormat.CLASH_IPCIDR,
        }

        return DetectionResult(
            format=mapping[behavior],
            confidence=1.0,
            reason=f"检测到显式 behavior: {behavior}",
            features=features,
        )

    # --------------------------------------------------------
    # 3. 统计行特征
    # --------------------------------------------------------

    classical_count = 0
    domain_count = 0
    cidr_count = 0
    ip_count = 0
    yaml_list_count = 0

    for line in lines:
        clean = strip_quotes(strip_yaml_list_prefix(line))

        if line.startswith("- "):
            yaml_list_count += 1

        if looks_like_classical_rule(clean):
            classical_count += 1
            continue

        if looks_like_cidr(clean):
            cidr_count += 1
            continue

        if looks_like_ip(clean):
            ip_count += 1
            continue

        if looks_like_domain(clean):
            domain_count += 1
            continue

    features.update(
        {
            "classical_rule_count": classical_count,
            "domain_count": domain_count,
            "cidr_count": cidr_count,
            "ip_count": ip_count,
            "yaml_list_count": yaml_list_count,
        }
    )

    total = max(
        len(lines),
        1,
    )

    classical_ratio = classical_count / total

    domain_ratio = domain_count / total

    cidr_ratio = cidr_count / total

    # --------------------------------------------------------
    # 4. payload YAML
    # --------------------------------------------------------

    if has_yaml_payload(text):
        # classical payload
        if classical_count > 0:
            return DetectionResult(
                format=SourceFormat.CLASH_CLASSICAL,
                confidence=max(
                    0.85,
                    min(
                        1.0,
                        0.85 + classical_ratio * 0.15,
                    ),
                ),
                reason=(
                    "检测到 payload:，且 payload 内存在 "
                    "DOMAIN/IP-CIDR 等 classical 规则"
                ),
                features=features,
            )

        # ipcidr payload
        if cidr_count > 0 and domain_count == 0:
            return DetectionResult(
                format=SourceFormat.CLASH_IPCIDR,
                confidence=max(
                    0.85,
                    min(
                        1.0,
                        0.85 + cidr_ratio * 0.15,
                    ),
                ),
                reason=("检测到 payload:，内容主要为裸 CIDR"),
                features=features,
            )

        # domain payload
        if domain_count > 0 and cidr_count == 0:
            return DetectionResult(
                format=SourceFormat.CLASH_DOMAIN,
                confidence=max(
                    0.85,
                    min(
                        1.0,
                        0.85 + domain_ratio * 0.15,
                    ),
                ),
                reason=("检测到 payload:，内容主要为裸域名"),
                features=features,
            )

        # payload 有，但内容混杂/未知
        return DetectionResult(
            format=SourceFormat.YAML,
            confidence=0.7,
            reason=("检测到 payload: YAML，但内容无法明确判断 classical/domain/ipcidr"),
            features=features,
        )

    # --------------------------------------------------------
    # 5. 无 payload 的 classical / Surge 风格
    # --------------------------------------------------------

    if classical_count > 0:
        # 如果绝大多数行都是 TYPE,value，
        # 很可能是 Surge / Loon / Clash list。
        if classical_ratio >= 0.6:
            return DetectionResult(
                format=SourceFormat.SURGE,
                confidence=min(
                    0.95,
                    0.75 + classical_ratio * 0.2,
                ),
                reason=("多数有效行符合 TYPE,value 格式，判定为 Surge/兼容 list 风格"),
                features=features,
            )

        return DetectionResult(
            format=SourceFormat.MIXED_TEXT,
            confidence=0.75,
            reason=("存在 classical 风格规则，但文件同时包含大量其他内容"),
            features=features,
        )

    # --------------------------------------------------------
    # 6. 纯 CIDR
    # --------------------------------------------------------

    if cidr_count > 0 and cidr_ratio >= 0.7:
        return DetectionResult(
            format=SourceFormat.PLAIN_CIDR,
            confidence=min(
                0.98,
                0.8 + cidr_ratio * 0.18,
            ),
            reason="多数有效行是 IPv4/IPv6 CIDR",
            features=features,
        )

    # --------------------------------------------------------
    # 7. 纯域名
    # --------------------------------------------------------

    if domain_count > 0 and domain_ratio >= 0.7:
        return DetectionResult(
            format=SourceFormat.PLAIN_DOMAIN,
            confidence=min(
                0.98,
                0.8 + domain_ratio * 0.18,
            ),
            reason="多数有效行是裸域名",
            features=features,
        )

    # --------------------------------------------------------
    # 8. 普通 YAML
    # --------------------------------------------------------

    if looks_like_yaml_document(text):
        return DetectionResult(
            format=SourceFormat.YAML,
            confidence=0.65,
            reason=("内容具有 YAML 键值结构，但未识别为标准 Clash provider"),
            features=features,
        )

    # --------------------------------------------------------
    # 9. 混合文本
    # --------------------------------------------------------

    if classical_count or domain_count or cidr_count or ip_count:
        return DetectionResult(
            format=SourceFormat.MIXED_TEXT,
            confidence=0.6,
            reason=("检测到部分规则特征，但整体格式混合"),
            features=features,
        )

    return DetectionResult(
        format=SourceFormat.UNKNOWN,
        confidence=0.3,
        reason="未检测到已知规则格式特征",
        features=features,
    )


# ============================================================
# 辅助接口
# ============================================================


def detect_source_format(text: str) -> SourceFormat:
    """
    简化接口。

    只想拿 SourceFormat 时使用：

        fmt = detect_source_format(text)
    """
    return detect_format(text).format


def explain_detection(text: str) -> str:
    """
    调试时返回人类可读说明。
    """
    result = detect_format(text)

    lines = [
        f"format: {result.format.value}",
        f"confidence: {result.confidence:.2f}",
        f"reason: {result.reason}",
        "features:",
    ]

    for key, value in sorted(result.features.items()):
        lines.append(f"  - {key}: {value}")

    return "\n".join(lines)
