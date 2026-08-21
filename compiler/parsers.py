from __future__ import annotations

import ipaddress
import re

from .detect import (
    COMMENT_PREFIXES,
    detect_format,
    looks_like_cidr,
    looks_like_classical_rule,
    looks_like_domain,
    normalize_text,
    strip_quotes,
    strip_yaml_list_prefix,
)
from .models import (
    ParseIssue,
    ParseResult,
    Rule,
    RuleSource,
    RuleType,
    SourceFormat,
)

# ============================================================
# 规则类型映射
# ============================================================

RULE_TYPE_MAP: dict[str, RuleType] = {
    "DOMAIN": RuleType.DOMAIN,
    "DOMAIN-SUFFIX": RuleType.DOMAIN_SUFFIX,
    "DOMAIN-KEYWORD": RuleType.DOMAIN_KEYWORD,
    "IP-CIDR": RuleType.IP_CIDR,
    "IP-CIDR6": RuleType.IP_CIDR6,
    "IP-ASN": RuleType.IP_ASN,
    "SRC-IP-CIDR": RuleType.SRC_IP_CIDR,
    "SRC-IP-CIDR6": RuleType.SRC_IP_CIDR6,
    "PROCESS-NAME": RuleType.PROCESS_NAME,
    "PROCESS-PATH": RuleType.PROCESS_PATH,
    "DST-PORT": RuleType.DST_PORT,
    "SRC-PORT": RuleType.SRC_PORT,
    "NETWORK": RuleType.NETWORK,
    "GEOIP": RuleType.GEOIP,
    "GEOSITE": RuleType.GEOSITE,
    "RULE-SET": RuleType.RULE_SET,
    "RULESET": RuleType.RULE_SET,
    "URL-REGEX": RuleType.URL_REGEX,
}


# ============================================================
# 通用工具
# ============================================================


def _make_source(
    source: RuleSource | None,
    *,
    line_number: int | None = None,
) -> RuleSource | None:
    """
    为当前行复制来源信息，并附加行号。

    避免所有 Rule 共用同一个 RuleSource 实例，
    导致 line_number 相互覆盖。
    """
    if source is None:
        return None

    return RuleSource(
        name=source.name,
        url=source.url,
        file=source.file,
        format=source.format,
        intent=source.intent,
        line_number=line_number,
        metadata=dict(source.metadata),
    )


def _clean_line(line: str) -> str:
    """
    清理单行：
    - trim
    - 去 YAML "- "
    - 去最外层引号
    """
    return strip_quotes(strip_yaml_list_prefix(line.strip())).strip()


def _split_rule_parts(line: str) -> list[str]:
    """
    按逗号拆 classical / Surge 规则。

    注意：
    URL-REGEX 等规则的 value 理论上可能含逗号，
    所以不能对所有类型无限 split。

    当前先采用：
    - 第一段 = type
    - 第二段 = value
    - 后续 = options

    对高级规则后面可以再专门扩展。
    """
    parts = [part.strip() for part in line.split(",")]

    return parts


def _is_comment_or_empty(line: str) -> bool:
    line = line.strip()

    if not line:
        return True

    return line.startswith(COMMENT_PREFIXES)


def _parse_domain_provider_value(value: str) -> tuple[RuleType, str]:
    """
    Clash domain behavior 常见写法：

        example.com
        +.example.com
        *.example.com

    统一转换：
        example.com      -> DOMAIN-SUFFIX
        +.example.com    -> DOMAIN-SUFFIX
        *.example.com    -> DOMAIN-SUFFIX

    这里选择 DOMAIN-SUFFIX，
    因为 domain behavior 通常表达域名集合/后缀语义。
    """
    value = strip_quotes(value.strip())

    if value.startswith(
        (
            "+.",
            "*.",
        )
    ):
        value = value[2:]

    return RuleType.DOMAIN_SUFFIX, value


def _cidr_rule_type(value: str) -> RuleType:
    """
    根据 CIDR 判断 IPv4 / IPv6。
    """
    network = ipaddress.ip_network(
        value,
        strict=False,
    )

    if network.version == 4:
        return RuleType.IP_CIDR

    return RuleType.IP_CIDR6


# ============================================================
# 单条规则解析
# ============================================================


def parse_classical_rule_line(
    line: str,
    *,
    source: RuleSource | None = None,
    line_number: int | None = None,
) -> Rule | ParseIssue | None:
    """
    解析：

        DOMAIN-SUFFIX,example.com
        IP-CIDR,1.2.3.0/24,no-resolve
        PROCESS-NAME,chrome.exe
    """

    if _is_comment_or_empty(line):
        return None

    raw = line.rstrip("\n")

    clean = _clean_line(line)

    if not clean:
        return None

    if "," not in clean:
        return ParseIssue(
            message="不是 classical TYPE,value 规则",
            raw=raw,
            source=_make_source(
                source,
                line_number=line_number,
            ),
        )

    parts = _split_rule_parts(clean)

    if len(parts) < 2:
        return ParseIssue(
            message="规则字段不足",
            raw=raw,
            source=_make_source(
                source,
                line_number=line_number,
            ),
        )

    type_name = parts[0].upper().strip()

    value = parts[1].strip()

    options = [part.strip() for part in parts[2:] if part.strip()]

    rule_type = RULE_TYPE_MAP.get(
        type_name,
        RuleType.UNKNOWN,
    )

    if rule_type == RuleType.UNKNOWN:
        return Rule(
            type=RuleType.UNKNOWN,
            value=value,
            options=options,
            source=_make_source(
                source,
                line_number=line_number,
            ),
            raw=raw,
            enabled=False,
            tags={"unsupported-type"},
            metadata={
                "original_type": type_name,
                "intent": source.intent if source else "unknown",
            },
        )

    if not value:
        return ParseIssue(
            message=f"{type_name} 缺少 value",
            raw=raw,
            source=_make_source(
                source,
                line_number=line_number,
            ),
        )

    return Rule(
        type=rule_type,
        value=value,
        options=options,
        source=_make_source(
            source,
            line_number=line_number,
        ),
        raw=raw,
    )


def parse_domain_line(
    line: str,
    *,
    source: RuleSource | None = None,
    line_number: int | None = None,
) -> Rule | ParseIssue | None:
    """
    解析裸域名。

    例如：
        google.com
        +.google.com
        *.google.com
    """

    if _is_comment_or_empty(line):
        return None

    raw = line.rstrip("\n")

    clean = _clean_line(line)

    if not clean:
        return None

    if not looks_like_domain(clean):
        return ParseIssue(
            message="不是有效的裸域名规则",
            raw=raw,
            source=_make_source(
                source,
                line_number=line_number,
            ),
        )

    rule_type, value = _parse_domain_provider_value(clean)

    return Rule(
        type=rule_type,
        value=value,
        source=_make_source(
            source,
            line_number=line_number,
        ),
        raw=raw,
    )


def parse_cidr_line(
    line: str,
    *,
    source: RuleSource | None = None,
    line_number: int | None = None,
) -> Rule | ParseIssue | None:
    """
    解析裸 CIDR。

    例如：
        1.1.1.0/24
        2001:4860::/32
    """

    if _is_comment_or_empty(line):
        return None

    raw = line.rstrip("\n")

    clean = _clean_line(line)

    if not clean:
        return None

    if not looks_like_cidr(clean):
        return ParseIssue(
            message="不是有效 CIDR",
            raw=raw,
            source=_make_source(
                source,
                line_number=line_number,
            ),
        )

    try:
        rule_type = _cidr_rule_type(clean)

    except ValueError:
        return ParseIssue(
            message="CIDR 解析失败",
            raw=raw,
            source=_make_source(
                source,
                line_number=line_number,
            ),
        )

    return Rule(
        type=rule_type,
        value=clean,
        options=["no-resolve"],
        source=_make_source(
            source,
            line_number=line_number,
        ),
        raw=raw,
    )


# ============================================================
# YAML payload 提取
# ============================================================


def extract_payload_lines(text: str) -> list[tuple[int, str]]:
    """
    从简单 Clash/Mihomo YAML 中提取：

        payload:
          - DOMAIN-SUFFIX,example.com
          - google.com

    返回：
        [(line_number, line), ...]

    这里故意不依赖 PyYAML。
    原因：
    大多数 rule-provider 都是非常简单的 payload 列表。

    若以后遇到复杂 YAML anchor / flow-style，
    再在 parsers.py 增加 PyYAML fallback。
    """

    text = normalize_text(text)

    lines = text.split("\n")

    payload_index: int | None = None

    payload_indent = 0

    for index, raw_line in enumerate(
        lines,
        start=1,
    ):
        match = re.match(
            r"^(\s*)payload\s*:\s*$",
            raw_line,
            flags=re.IGNORECASE,
        )

        if match:
            payload_index = index
            payload_indent = len(match.group(1))
            break

    if payload_index is None:
        return []

    output: list[tuple[int, str]] = []

    for index in range(
        payload_index + 1,
        len(lines) + 1,
    ):
        raw_line = lines[index - 1]

        stripped = raw_line.strip()

        if not stripped:
            continue

        # 注释允许跳过
        if stripped.startswith(COMMENT_PREFIXES):
            continue

        indent = len(raw_line) - len(raw_line.lstrip())

        # 已经回到 payload 同级或更外层，
        # 认为 payload 结束。
        if indent <= payload_indent and not stripped.startswith("-"):
            break

        if stripped.startswith("-"):
            output.append(
                (
                    index,
                    stripped,
                )
            )

    return output


# ============================================================
# 各格式解析
# ============================================================


def parse_clash_classical(
    text: str,
    *,
    source: RuleSource | None = None,
) -> ParseResult:
    """
    Clash classical payload。
    """

    result = ParseResult(
        detected_format=SourceFormat.CLASH_CLASSICAL,
        source=source,
    )

    payload_lines = extract_payload_lines(text)

    if not payload_lines:
        result.issues.append(
            ParseIssue(
                message="未找到 payload 列表",
                source=source,
            )
        )
        return result

    for line_number, line in payload_lines:
        parsed = parse_classical_rule_line(
            line,
            source=source,
            line_number=line_number,
        )

        _append_parsed(
            result,
            parsed,
        )

    return result


def parse_clash_domain(
    text: str,
    *,
    source: RuleSource | None = None,
) -> ParseResult:
    """
    Clash domain behavior payload。
    """

    result = ParseResult(
        detected_format=SourceFormat.CLASH_DOMAIN,
        source=source,
    )

    payload_lines = extract_payload_lines(text)

    if not payload_lines:
        result.issues.append(
            ParseIssue(
                message="未找到 payload 列表",
                source=source,
            )
        )
        return result

    for line_number, line in payload_lines:
        parsed = parse_domain_line(
            line,
            source=source,
            line_number=line_number,
        )

        _append_parsed(
            result,
            parsed,
        )

    return result


def parse_clash_ipcidr(
    text: str,
    *,
    source: RuleSource | None = None,
) -> ParseResult:
    """
    Clash ipcidr behavior payload。
    """

    result = ParseResult(
        detected_format=SourceFormat.CLASH_IPCIDR,
        source=source,
    )

    payload_lines = extract_payload_lines(text)

    if not payload_lines:
        result.issues.append(
            ParseIssue(
                message="未找到 payload 列表",
                source=source,
            )
        )
        return result

    for line_number, line in payload_lines:
        parsed = parse_cidr_line(
            line,
            source=source,
            line_number=line_number,
        )

        _append_parsed(
            result,
            parsed,
        )

    return result


def parse_surge_link(
    text: str,
    *,
    source: RuleSource | None = None,
    detected_format: SourceFormat = SourceFormat.SURGE,
) -> ParseResult:
    """
    无 payload 包装的 TYPE,value 列表。

    可兼容：
    - Surge list
    - ACL4SSR .list
    - Loon 大部分基础规则
    - 普通 classical 文本
    """

    result = ParseResult(
        detected_format=detected_format,
        source=source,
    )

    for line_number, raw_line in enumerate(
        normalize_text(text).split("\n"),
        start=1,
    ):
        if _is_comment_or_empty(raw_line):
            continue

        parsed = parse_classical_rule_line(
            raw_line,
            source=source,
            line_number=line_number,
        )

        _append_parsed(
            result,
            parsed,
        )

    return result


def parse_plain_domains(
    text: str,
    *,
    source: RuleSource | None = None,
) -> ParseResult:
    result = ParseResult(
        detected_format=SourceFormat.PLAIN_DOMAIN,
        source=source,
    )

    for line_number, raw_line in enumerate(
        normalize_text(text).split("\n"),
        start=1,
    ):
        if _is_comment_or_empty(raw_line):
            continue

        parsed = parse_domain_line(
            raw_line,
            source=source,
            line_number=line_number,
        )

        _append_parsed(
            result,
            parsed,
        )

    return result


def parse_plain_cidrs(
    text: str,
    *,
    source: RuleSource | None = None,
) -> ParseResult:
    result = ParseResult(
        detected_format=SourceFormat.PLAIN_CIDR,
        source=source,
    )

    for line_number, raw_line in enumerate(
        normalize_text(text).split("\n"),
        start=1,
    ):
        if _is_comment_or_empty(raw_line):
            continue

        parsed = parse_cidr_line(
            raw_line,
            source=source,
            line_number=line_number,
        )

        _append_parsed(
            result,
            parsed,
        )

    return result


def parse_mixed_text(
    text: str,
    *,
    source: RuleSource | None = None,
) -> ParseResult:
    """
    尽最大努力解析混合文本。

    优先级：
    1. classical TYPE,value
    2. CIDR
    3. domain
    4. 无法识别 -> issue
    """

    result = ParseResult(
        detected_format=SourceFormat.MIXED_TEXT,
        source=source,
    )

    for line_number, raw_line in enumerate(
        normalize_text(text).split("\n"),
        start=1,
    ):
        if _is_comment_or_empty(raw_line):
            continue

        clean = _clean_line(raw_line)

        parsed: Rule | ParseIssue | None

        if looks_like_classical_rule(clean):
            parsed = parse_classical_rule_line(
                raw_line,
                source=source,
                line_number=line_number,
            )

        elif looks_like_cidr(clean):
            parsed = parse_cidr_line(
                raw_line,
                source=source,
                line_number=line_number,
            )

        elif looks_like_domain(clean):
            parsed = parse_domain_line(
                raw_line,
                source=source,
                line_number=line_number,
            )

        else:
            parsed = ParseIssue(
                message="无法识别的混合规则行",
                raw=raw_line,
                source=_make_source(
                    source,
                    line_number=line_number,
                ),
            )

        _append_parsed(
            result,
            parsed,
        )

    return result


# ============================================================
# YAML fallback
# ============================================================


def parse_generic_yaml(
    text: str,
    *,
    source: RuleSource | None = None,
) -> ParseResult:
    """
    对检测为普通 YAML 的文件做保守处理。

    如果实际上存在 payload，
    再根据 payload 内容逐行自动推断。
    """

    result = ParseResult(
        detected_format=SourceFormat.YAML,
        source=source,
    )

    payload_lines = extract_payload_lines(text)

    if not payload_lines:
        result.issues.append(
            ParseIssue(
                message=("检测为 YAML，但不存在可解析的 payload 列表"),
                source=source,
            )
        )
        return result

    for line_number, raw_line in payload_lines:
        clean = _clean_line(raw_line)

        parsed: Rule | ParseIssue | None

        if looks_like_classical_rule(clean):
            parsed = parse_classical_rule_line(
                raw_line,
                source=source,
                line_number=line_number,
            )

        elif looks_like_cidr(clean):
            parsed = parse_cidr_line(
                raw_line,
                source=source,
                line_number=line_number,
            )

        elif looks_like_domain(clean):
            parsed = parse_domain_line(
                raw_line,
                source=source,
                line_number=line_number,
            )

        else:
            parsed = ParseIssue(
                message="payload 中存在无法识别的规则",
                raw=raw_line,
                source=_make_source(
                    source,
                    line_number=line_number,
                ),
            )

        _append_parsed(
            result,
            parsed,
        )

    return result


# ============================================================
# 结果辅助
# ============================================================


def _append_parsed(
    result: ParseResult,
    parsed: Rule | ParseIssue | None,
) -> None:
    """
    统一添加解析结果。
    """

    if parsed is None:
        return

    if isinstance(
        parsed,
        Rule,
    ):
        result.rules.append(parsed)

        if parsed.type == RuleType.UNKNOWN:
            result.issues.append(
                ParseIssue(
                    message=(
                        "发现暂不支持的规则类型: "
                        f"{parsed.metadata.get('original_type', 'UNKNOWN')}"
                    ),
                    raw=parsed.raw,
                    source=parsed.source,
                    level="warning",
                )
            )

        return

    result.issues.append(parsed)


# ============================================================
# 总入口
# ============================================================


def parse_rules(
    text: str,
    *,
    source: RuleSource | None = None,
    format_hint: SourceFormat | None = None,
) -> ParseResult:
    """
    万能解析入口。

    如果调用者明确知道格式：
        format_hint=...

    否则自动 detect。
    """

    if format_hint is None:
        detection = detect_format(text)
        detected_format = detection.format
    else:
        detected_format = format_hint

    if source is not None:
        source = RuleSource(
            name=source.name,
            url=source.url,
            file=source.file,
            format=detected_format,
            line_number=source.line_number,
            metadata=dict(source.metadata),
        )

    if detected_format == SourceFormat.CLASH_CLASSICAL:
        return parse_clash_classical(
            text,
            source=source,
        )

    if detected_format == SourceFormat.CLASH_DOMAIN:
        return parse_clash_domain(
            text,
            source=source,
        )

    if detected_format == SourceFormat.CLASH_IPCIDR:
        return parse_clash_ipcidr(
            text,
            source=source,
        )

    if detected_format in {
        SourceFormat.SURGE,
        SourceFormat.LOON,
        SourceFormat.QUANTUMULT_X,
    }:
        return parse_surge_link(
            text,
            source=source,
            detected_format=detected_format,
        )

    if detected_format == SourceFormat.PLAIN_DOMAIN:
        return parse_plain_domains(
            text,
            source=source,
        )

    if detected_format == SourceFormat.PLAIN_CIDR:
        return parse_plain_cidrs(
            text,
            source=source,
        )

    if detected_format == SourceFormat.MIXED_TEXT:
        return parse_mixed_text(
            text,
            source=source,
        )

    if detected_format == SourceFormat.YAML:
        return parse_generic_yaml(
            text,
            source=source,
        )

    if detected_format == SourceFormat.JSON:
        return ParseResult(
            detected_format=SourceFormat.JSON,
            source=source,
            issues=[
                ParseIssue(
                    message=("JSON 已检测成功，但 JSON 规则解析器尚未实现"),
                    source=source,
                    level="warning",
                )
            ],
        )

    return ParseResult(
        detected_format=SourceFormat.UNKNOWN,
        source=source,
        issues=[
            ParseIssue(
                message="无法识别输入规则格式",
                source=source,
                level="error",
            )
        ],
    )
