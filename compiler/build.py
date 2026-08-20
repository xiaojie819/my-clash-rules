from __future__ import annotations

import json
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from .detect import detect_format
from .models import (
    BuildStats,
    ParseIssue,
    Rule,
    RuleSource,
    RuleType,
    SourceFormat,
)
from .normalize import normalize_rules
from .optimize import (
    OptimizeMode,
    OptimizeResult,
    optimize_rules,
)
from .parsers import parse_rules


# ============================================================
# 输出模式
# ============================================================

class OutputMode(str, Enum):
    """
    STRICT:
        只输出我们当前最稳妥的核心 classical 类型：

        DOMAIN
        DOMAIN-SUFFIX
        DOMAIN-KEYWORD
        IP-CIDR
        IP-CIDR6

    EXTENDED:
        输出编译器已认识、且 enabled=True 的扩展类型，
        例如 PROCESS-NAME / GEOIP / GEOSITE 等。

    当前你的规则仓库建议默认 STRICT。
    """

    STRICT = "strict"
    EXTENDED = "extended"


# ============================================================
# 构建结果
# ============================================================

@dataclass(slots=True)
class BuildResult:
    """
    一次完整规则构建的结果。
    """

    rules: list[Rule] = field(default_factory=list)

    issues: list[ParseIssue] = field(default_factory=list)

    stats: BuildStats | None = None

    detected_format: SourceFormat = SourceFormat.UNKNOWN

    output_mode: OutputMode = OutputMode.STRICT

    optimize_mode: OptimizeMode = OptimizeMode.SAFE

    # 已渲染好的最终 YAML
    content: str = ""

    source: RuleSource | None = None

    @property
    def success(self) -> bool:
        """
        是否可以认为本次构建成功。

        warning / info 不算失败。
        """
        return not any(
            issue.level.lower() == "error"
            for issue in self.issues
        )

    @property
    def final_rule_count(self) -> int:
        return len(self.rules)


# ============================================================
# 网络 / 文件读取
# ============================================================

DEFAULT_USER_AGENT = (
    "my-clash-rules/1.0 "
    "(universal-rule-compiler)"
)


def fetch_url_text(
    url: str,
    *,
    timeout: int = 30,
    user_agent: str = DEFAULT_USER_AGENT,
) -> str:
    """
    下载一个 HTTP/HTTPS 文本规则源。

    暂时只使用 Python 标准库，
    不依赖 requests。

    以后 sources.yaml 批量构建会直接调用这里。
    """

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
            "Accept": (
                "text/plain,"
                "application/yaml,"
                "application/json,"
                "*/*"
            ),
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:
            raw = response.read()

            # 优先相信服务器 charset
            charset = response.headers.get_content_charset()

            if charset:
                try:
                    return raw.decode(charset)
                except (
                    LookupError,
                    UnicodeDecodeError,
                ):
                    pass

            # 常见规则仓库基本都是 UTF-8
            try:
                return raw.decode("utf-8")

            except UnicodeDecodeError:
                # 最后做一个保守 fallback。
                # replacement 会保留构建能力，同时后面报告异常。
                return raw.decode(
                    "utf-8",
                    errors="replace",
                )

    except urllib.error.HTTPError as exc:
        raise RuntimeError(
            f"下载失败 HTTP {exc.code}: {url}"
        ) from exc

    except urllib.error.URLError as exc:
        raise RuntimeError(
            f"下载失败: {url} ({exc.reason})"
        ) from exc

    except TimeoutError as exc:
        raise RuntimeError(
            f"下载超时: {url}"
        ) from exc


def read_file_text(
    path: str | Path,
) -> str:
    """
    读取本地规则文件。
    """
    path = Path(path)

    if not path.exists():
        raise FileNotFoundError(
            f"规则文件不存在: {path}"
        )

    if not path.is_file():
        raise ValueError(
            f"不是普通文件: {path}"
        )

    return path.read_text(
        encoding="utf-8-sig",
    )


# ============================================================
# 输出过滤
# ============================================================

def filter_rules_for_output(
    rules: list[Rule],
    *,
    mode: OutputMode,
) -> tuple[
    list[Rule],
    list[ParseIssue],
    int,
]:
    """
    按输出模式过滤规则。

    返回：
        final_rules
        issues
        unsupported_count
    """

    output: list[Rule] = []

    issues: list[ParseIssue] = []

    unsupported_count = 0

    for rule in rules:

        # normalize 阶段判定无效
        if not rule.enabled:
            continue

        # UNKNOWN 永远不能直接输出
        if rule.type == RuleType.UNKNOWN:
            unsupported_count += 1

            issues.append(
                ParseIssue(
                    message=(
                        "UNKNOWN 规则未输出"
                    ),
                    raw=rule.raw,
                    source=rule.source,
                    level="warning",
                )
            )
            continue

        # STRICT 只允许核心类型
        if (
            mode == OutputMode.STRICT
            and not rule.is_core_compatible()
        ):
            unsupported_count += 1

            issues.append(
                ParseIssue(
                    message=(
                        "STRICT 模式跳过扩展规则: "
                        f"{rule.type.value},"
                        f"{rule.value}"
                    ),
                    raw=rule.raw,
                    source=rule.source,
                    level="info",
                )
            )
            continue

        output.append(
            rule
        )

    return (
        output,
        issues,
        unsupported_count,
    )


# ============================================================
# YAML 输出
# ============================================================

def _yaml_quote(
    value: str,
) -> str:
    """
    使用 JSON 双引号编码生成 YAML 安全字符串。

    JSON 字符串本身是合法 YAML 标量。

    这样可以安全处理：
        :
        #
        *
        !
        正则字符
        中文
        特殊符号
    """
    return json.dumps(
        value,
        ensure_ascii=False,
    )


def render_classical_yaml(
    rules: list[Rule],
    *,
    header_comments: list[str] | None = None,
) -> str:
    """
    生成统一的 Clash/Mihomo classical payload YAML。

    示例：

        payload:
          - "DOMAIN-SUFFIX,example.com"
          - "IP-CIDR,1.2.3.0/24,no-resolve"
    """

    lines: list[str] = []

    if header_comments:
        for comment in header_comments:
            comment = comment.strip()

            if not comment:
                lines.append("#")
            else:
                lines.append(
                    f"# {comment}"
                )

        lines.append("")

    lines.append("payload:")

    for rule in rules:
        classical_line = (
            rule.to_classical_line()
        )

        lines.append(
            "  - "
            + _yaml_quote(
                classical_line
            )
        )

    # POSIX 文本文件结尾保留换行
    return "\n".join(lines) + "\n"


# ============================================================
# Stats
# ============================================================

def _count_invalid_rules(
    rules: list[Rule],
) -> int:
    return sum(
        1
        for rule in rules
        if not rule.enabled
    )


def _make_stats(
    *,
    group: str,
    parsed_rules: list[Rule],
    normalized_rules: list[Rule],
    optimized: OptimizeResult,
    unsupported_count: int,
    source_count: int = 1,
) -> BuildStats:

    stats = BuildStats(
        group=group,
        source_count=source_count,
        raw_rule_count=len(
            parsed_rules
        ),
        normalized_rule_count=len(
            normalized_rules
        ),
        duplicate_count=(
            optimized.duplicate_count
        ),
        covered_rule_count=(
            optimized.covered_domain_count
            + optimized.covered_cidr_count
        ),
        invalid_rule_count=(
            _count_invalid_rules(
                normalized_rules
            )
        ),
        unsupported_rule_count=(
            unsupported_count
        ),
        final_rule_count=0,
    )

    return stats


# ============================================================
# 核心编译函数
# ============================================================

def compile_text(
    text: str,
    *,
    group: str = "default",
    source: RuleSource | None = None,
    format_hint: SourceFormat | None = None,
    output_mode: OutputMode = OutputMode.STRICT,
    optimize_mode: OptimizeMode = OptimizeMode.SAFE,
    sort_output: bool = True,
    header_comments: list[str] | None = None,
) -> BuildResult:
    """
    编译一段规则文本。

    完整流水线：

        detect
        ↓
        parse
        ↓
        normalize
        ↓
        optimize
        ↓
        output filter
        ↓
        YAML render
    """

    issues: list[ParseIssue] = []

    # --------------------------------------------------------
    # 1. Detect
    # --------------------------------------------------------

    if format_hint is None:
        detection = detect_format(
            text
        )

        detected_format = (
            detection.format
        )

    else:
        detected_format = (
            format_hint
        )

    if source is None:
        source = RuleSource(
            name=group,
            format=detected_format,
        )

    else:
        source = RuleSource(
            name=source.name,
            url=source.url,
            file=source.file,
            format=detected_format,
            line_number=source.line_number,
            metadata=dict(
                source.metadata
            ),
        )

    # --------------------------------------------------------
    # 2. Parse
    # --------------------------------------------------------

    parsed = parse_rules(
        text,
        source=source,
        format_hint=detected_format,
    )

    issues.extend(
        parsed.issues
    )

    # --------------------------------------------------------
    # 3. Normalize
    # --------------------------------------------------------

    (
        normalized_rules,
        normalize_issues,
    ) = normalize_rules(
        parsed.rules
    )

    issues.extend(
        normalize_issues
    )

    # --------------------------------------------------------
    # 4. Optimize
    # --------------------------------------------------------

    optimized = optimize_rules(
        normalized_rules,
        mode=optimize_mode,
        sort_output=sort_output,
    )

    issues.extend(
        optimized.issues
    )

    # --------------------------------------------------------
    # 5. Output filter
    # --------------------------------------------------------

    (
        final_rules,
        filter_issues,
        unsupported_count,
    ) = filter_rules_for_output(
        optimized.rules,
        mode=output_mode,
    )

    issues.extend(
        filter_issues
    )

    # --------------------------------------------------------
    # 6. Stats
    # --------------------------------------------------------

    stats = _make_stats(
        group=group,
        parsed_rules=parsed.rules,
        normalized_rules=normalized_rules,
        optimized=optimized,
        unsupported_count=(
            unsupported_count
        ),
    )

    stats.final_rule_count = len(
        final_rules
    )

    stats.issues.extend(
        issue.message
        for issue in issues
    )

    # --------------------------------------------------------
    # 7. Render
    # --------------------------------------------------------

    if header_comments is None:
        header_comments = [
            (
                "Generated by "
                "my-clash-rules universal compiler"
            ),
            f"Group: {group}",
            (
                "Output mode: "
                f"{output_mode.value}"
            ),
            (
                "Optimize mode: "
                f"{optimize_mode.value}"
            ),
            (
                "Rules: "
                f"{len(final_rules)}"
            ),
        ]

    content = render_classical_yaml(
        final_rules,
        header_comments=header_comments,
    )

    return BuildResult(
        rules=final_rules,
        issues=issues,
        stats=stats,
        detected_format=(
            detected_format
        ),
        output_mode=output_mode,
        optimize_mode=optimize_mode,
        content=content,
        source=source,
    )


# ============================================================
# 编译本地文件
# ============================================================

def compile_file(
    path: str | Path,
    *,
    group: str | None = None,
    output_mode: OutputMode = OutputMode.STRICT,
    optimize_mode: OptimizeMode = OptimizeMode.SAFE,
    format_hint: SourceFormat | None = None,
    sort_output: bool = True,
) -> BuildResult:

    path = Path(path)

    text = read_file_text(
        path
    )

    if group is None:
        group = path.stem

    source = RuleSource(
        name=group,
        file=str(path),
    )

    return compile_text(
        text,
        group=group,
        source=source,
        format_hint=format_hint,
        output_mode=output_mode,
        optimize_mode=optimize_mode,
        sort_output=sort_output,
    )


# ============================================================
# 编译 URL
# ============================================================

def compile_url(
    url: str,
    *,
    group: str = "remote",
    output_mode: OutputMode = OutputMode.STRICT,
    optimize_mode: OptimizeMode = OptimizeMode.SAFE,
    format_hint: SourceFormat | None = None,
    sort_output: bool = True,
    timeout: int = 30,
) -> BuildResult:

    text = fetch_url_text(
        url,
        timeout=timeout,
    )

    source = RuleSource(
        name=group,
        url=url,
    )

    return compile_text(
        text,
        group=group,
        source=source,
        format_hint=format_hint,
        output_mode=output_mode,
        optimize_mode=optimize_mode,
        sort_output=sort_output,
    )


# ============================================================
# 写入结果
# ============================================================

def write_build_result(
    result: BuildResult,
    output_path: str | Path,
) -> Path:
    """
    把 BuildResult 写成最终 YAML 文件。
    """

    output_path = Path(
        output_path
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    output_path.write_text(
        result.content,
        encoding="utf-8",
        newline="\n",
    )

    return output_path


# ============================================================
# 构建报告
# ============================================================

def build_report_dict(
    result: BuildResult,
) -> dict[str, object]:
    """
    生成后续 reports/*.json 可用的数据。
    """

    stats = (
        result.stats.as_dict()
        if result.stats
        else {}
    )

    level_counts = {
        "error": 0,
        "warning": 0,
        "info": 0,
        "other": 0,
    }

    for issue in result.issues:
        level = (
            issue.level
            .strip()
            .lower()
        )

        if level in level_counts:
            level_counts[
                level
            ] += 1

        else:
            level_counts[
                "other"
            ] += 1

    return {
        "success": result.success,
        "detected_format": (
            result.detected_format.value
        ),
        "output_mode": (
            result.output_mode.value
        ),
        "optimize_mode": (
            result.optimize_mode.value
        ),
        "final_rule_count": (
            result.final_rule_count
        ),
        "issue_levels": (
            level_counts
        ),
        "stats": stats,
        "issues": [
            {
                "level": issue.level,
                "message": issue.message,
                "raw": issue.raw,
                "source": (
                    issue.source.url
                    if (
                        issue.source
                        and issue.source.url
                    )
                    else (
                        issue.source.file
                        if (
                            issue.source
                            and issue.source.file
                        )
                        else ""
                    )
                ),
                "line_number": (
                    issue.source.line_number
                    if issue.source
                    else None
                ),
            }
            for issue in result.issues
        ],
    }


def write_build_report(
    result: BuildResult,
    output_path: str | Path,
) -> Path:
    """
    写 JSON 构建报告。
    """

    output_path = Path(
        output_path
    )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    data = build_report_dict(
        result
    )

    output_path.write_text(
        json.dumps(
            data,
            ensure_ascii=False,
            indent=2,
        )
        + "\n",
        encoding="utf-8",
        newline="\n",
    )

    return output_path


# ============================================================
# 简单调试摘要
# ============================================================

def build_summary(
    result: BuildResult,
) -> str:

    stats = result.stats

    lines = [
        "=== Rule Build Summary ===",
        (
            "success: "
            f"{result.success}"
        ),
        (
            "format: "
            f"{result.detected_format.value}"
        ),
        (
            "output mode: "
            f"{result.output_mode.value}"
        ),
        (
            "optimize mode: "
            f"{result.optimize_mode.value}"
        ),
    ]

    if stats:
        lines.extend(
            [
                (
                    "raw rules: "
                    f"{stats.raw_rule_count}"
                ),
                (
                    "normalized: "
                    f"{stats.normalized_rule_count}"
                ),
                (
                    "duplicates: "
                    f"{stats.duplicate_count}"
                ),
                (
                    "covered: "
                    f"{stats.covered_rule_count}"
                ),
                (
                    "invalid: "
                    f"{stats.invalid_rule_count}"
                ),
                (
                    "unsupported: "
                    f"{stats.unsupported_rule_count}"
                ),
                (
                    "final: "
                    f"{stats.final_rule_count}"
                ),
            ]
        )

    lines.append(
        f"issues: {len(result.issues)}"
    )

    return "\n".join(
        lines
    )
