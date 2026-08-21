from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RuleType(str, Enum):
    """
    统一规则类型。

    核心兼容类型：
    - DOMAIN
    - DOMAIN-SUFFIX
    - DOMAIN-KEYWORD
    - IP-CIDR
    - IP-CIDR6

    扩展类型先保留，后续由输出模式决定是否生成。
    """

    DOMAIN = "DOMAIN"
    DOMAIN_SUFFIX = "DOMAIN-SUFFIX"
    DOMAIN_KEYWORD = "DOMAIN-KEYWORD"

    IP_CIDR = "IP-CIDR"
    IP_CIDR6 = "IP-CIDR6"
    IP_ASN = "IP-ASN"

    PROCESS_NAME = "PROCESS-NAME"
    PROCESS_PATH = "PROCESS-PATH"

    SRC_IP_CIDR = "SRC-IP-CIDR"
    SRC_IP_CIDR6 = "SRC-IP-CIDR6"

    DST_PORT = "DST-PORT"
    SRC_PORT = "SRC-PORT"

    NETWORK = "NETWORK"

    GEOIP = "GEOIP"
    GEOSITE = "GEOSITE"

    RULE_SET = "RULE-SET"

    URL_REGEX = "URL-REGEX"

    UNKNOWN = "UNKNOWN"


class SourceFormat(str, Enum):
    """
    上游输入格式类型。
    detect.py 后续会负责自动识别。
    """

    CLASH_CLASSICAL = "clash-classical"
    CLASH_DOMAIN = "clash-domain"
    CLASH_IPCIDR = "clash-ipcidr"

    SURGE = "surge"
    QUANTUMULT_X = "quantumult-x"
    LOON = "loon"

    PLAIN_DOMAIN = "plain-domain"
    PLAIN_CIDR = "plain-cidr"
    MIXED_TEXT = "mixed-text"

    YAML = "yaml"
    JSON = "json"

    UNKNOWN = "unknown"


@dataclass(slots=True)
class RuleSource:
    """
    描述一条规则来自哪里。
    """

    name: str = ""
    url: str = ""
    file: str = ""
    format: SourceFormat = SourceFormat.UNKNOWN

    # 上游文件内的行号
    line_number: int | None = None

    # 来源默认语义：
    # proxy / direct / reject / unknown
    intent: str = "unknown"

    # 额外元信息
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Rule:
    """
    编译器内部统一规则对象。

    不管上游是什么格式，最终都先转换成 Rule。
    """

    type: RuleType
    value: str

    # 例如：
    # IP-CIDR,1.2.3.0/24,no-resolve
    # options = ["no-resolve"]
    options: list[str] = field(default_factory=list)

    # 来源信息
    source: RuleSource | None = None

    # 上游原始文本，方便排错和报告
    raw: str = ""

    # 是否有效
    enabled: bool = True

    # 解析/规范化时产生的标签
    tags: set[str] = field(default_factory=set)

    # 任意扩展信息
    metadata: dict[str, Any] = field(default_factory=dict)

    def canonical_key(self) -> tuple[str, str, tuple[str, ...]]:
        """
        用于基础去重。

        normalize.py 后续会先规范化 value/options，
        optimize.py 再使用这个 key 去重。
        """
        return (
            self.type.value,
            self.value,
            tuple(sorted(self.options)),
        )

    def to_classical_line(self) -> str:
        """
        输出为 Clash/Mihomo classical 单条规则。

        示例：
        DOMAIN-SUFFIX,example.com

        IP-CIDR,1.2.3.0/24,no-resolve
        """
        parts = [self.type.value, self.value]

        if self.options:
            parts.extend(self.options)

        return ",".join(parts)

    def is_domain_rule(self) -> bool:
        return self.type in {
            RuleType.DOMAIN,
            RuleType.DOMAIN_SUFFIX,
            RuleType.DOMAIN_KEYWORD,
        }

    def is_ip_rule(self) -> bool:
        return self.type in {
            RuleType.IP_CIDR,
            RuleType.IP_CIDR6,
            RuleType.SRC_IP_CIDR,
            RuleType.SRC_IP_CIDR6,
        }

    def is_core_compatible(self) -> bool:
        """
        当前项目最稳定的 classical 核心规则集。

        strict 输出模式以后只允许这些。
        """
        return self.type in {
            RuleType.DOMAIN,
            RuleType.DOMAIN_SUFFIX,
            RuleType.DOMAIN_KEYWORD,
            RuleType.IP_CIDR,
            RuleType.IP_CIDR6,
        }


@dataclass(slots=True)
class ParseIssue:
    """
    记录解析过程中的异常/未知规则。

    不能静默丢规则。
    """

    message: str

    raw: str = ""

    source: RuleSource | None = None

    level: str = "warning"

    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class ParseResult:
    """
    一个上游文件解析后的结果。
    """

    rules: list[Rule] = field(default_factory=list)

    issues: list[ParseIssue] = field(default_factory=list)

    detected_format: SourceFormat = SourceFormat.UNKNOWN

    source: RuleSource | None = None

    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def valid_rule_count(self) -> int:
        return sum(1 for rule in self.rules if rule.enabled)

    @property
    def issue_count(self) -> int:
        return len(self.issues)


@dataclass(slots=True)
class BuildStats:
    """
    单个规则组的构建统计。
    """

    group: str

    source_count: int = 0

    raw_rule_count: int = 0

    normalized_rule_count: int = 0

    duplicate_count: int = 0

    covered_rule_count: int = 0

    invalid_rule_count: int = 0

    unsupported_rule_count: int = 0

    final_rule_count: int = 0

    issues: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "group": self.group,
            "source_count": self.source_count,
            "raw_rule_count": self.raw_rule_count,
            "normalized_rule_count": self.normalized_rule_count,
            "duplicate_count": self.duplicate_count,
            "covered_rule_count": self.covered_rule_count,
            "invalid_rule_count": self.invalid_rule_count,
            "unsupported_rule_count": self.unsupported_rule_count,
            "final_rule_count": self.final_rule_count,
            "issues": self.issues,
        }
