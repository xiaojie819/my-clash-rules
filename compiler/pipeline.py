from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from .config import (
    AppConfig,
    GroupConfig,
    SourceConfig,
    enabled_groups,
    enabled_sources,
)
from .fetcher import fetch_url_text
from .extractor import extract_rules
from .models import (
    ParseIssue,
    Rule,
    RuleSource,
)
from .normalize import normalize_rules
from .optimize import (
    optimize_rules,
)
from .renderer import render_classical_yaml
from .sanitize import sanitize_text

# ============================================================
# Pipeline Result
# ============================================================


@dataclass(slots=True)
class SourceBuildResult:
    name: str

    success: bool

    rules: list[Rule] = field(default_factory=list)

    issues: list[ParseIssue] = field(default_factory=list)


@dataclass(slots=True)
class GroupBuildResult:
    name: str

    success: bool

    rules: list[Rule] = field(default_factory=list)

    issues: list[ParseIssue] = field(default_factory=list)

    source_results: list[SourceBuildResult] = field(default_factory=list)

    output: Path | None = None

    report: Path | None = None


@dataclass(slots=True)
class PipelineResult:
    success: bool

    groups: list[GroupBuildResult] = field(default_factory=list)


# ============================================================
# Source
# ============================================================


def build_single_source(
    source: SourceConfig,
    *,
    group: GroupConfig,
) -> SourceBuildResult:

    result = SourceBuildResult(
        name=source.name,
        success=False,
    )

    try:
        text = fetch_url_text(
            source.url,
            timeout=(source.timeout or group.timeout),
        )

        sanitize_result = sanitize_text(text)

        text = sanitize_result.text

        rule_source = RuleSource(
            name=source.name,
            url=source.url,
            intent=source.intent,
        )

        parsed = extract_rules(
            text,
            rule_source,
            format_hint=source.format,
        )

        normalized_rules, normalize_issues = normalize_rules(parsed.rules)

        result.rules = normalized_rules

        result.issues.extend(parsed.issues)

        result.issues.extend(normalize_issues)

        result.success = True

    except (
        OSError,
        ValueError,
        RuntimeError,
    ) as exc:
        result.issues.append(
            ParseIssue(
                message=(f"源 {source.name} 构建失败: {exc}"),
                level="error",
            )
        )

    return result


# ============================================================
# Group
# ============================================================


def build_group(
    group: GroupConfig,
) -> GroupBuildResult:

    result = GroupBuildResult(
        name=group.name,
        success=False,
    )

    all_rules: list[Rule] = []

    # --------------------------------------------------------
    # 1. 下载所有 source
    # --------------------------------------------------------

    for source in enabled_sources(group):
        source_result = build_single_source(
            source,
            group=group,
        )

        result.source_results.append(source_result)

        result.issues.extend(source_result.issues)

        if source_result.success:
            all_rules.extend(source_result.rules)

        elif not group.continue_on_source_error:
            result.issues.append(
                ParseIssue(
                    message=("源失败，根据配置终止 group"),
                    level="error",
                )
            )

            return result

    # --------------------------------------------------------
    # 没有规则
    # --------------------------------------------------------

    if not all_rules:
        result.issues.append(
            ParseIssue(
                message=("group 没有成功生成任何规则"),
                level="error",
            )
        )

        return result

    # --------------------------------------------------------
    # 2. 全局 normalize
    #
    # 再跑一次是故意的。
    #
    # 单源阶段方便发现源问题。
    # 全局阶段保证合并后的最终一致。
    # --------------------------------------------------------

    normalized_rules, normalize_issues = normalize_rules(all_rules)

    result.issues.extend(normalize_issues)

    # --------------------------------------------------------
    # 3. 全局 optimize
    # --------------------------------------------------------

    optimized = optimize_rules(
        normalized_rules,
        mode=group.optimize_mode,
        sort_output=(group.sort_output),
    )

    result.rules = optimized.rules

    result.issues.extend(optimized.issues)

    # --------------------------------------------------------
    # 4. 写输出
    # --------------------------------------------------------

    output_path = Path(group.output)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    content = render_classical_yaml(
        result.rules,
        header_comments=[
            ("Generated by universal rule compiler"),
            (f"Group: {group.name}"),
            (f"Sources: {len(result.source_results)}"),
            (f"Rules: {len(result.rules)}"),
        ],
    )

    output_path.write_text(
        content,
        encoding="utf-8",
    )

    result.output = output_path

    # --------------------------------------------------------
    # 5. 写报告
    # --------------------------------------------------------

    report_path = Path(group.report)

    report_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_data = {
        "group": group.name,
        "success": True,
        "rule_count": (len(result.rules)),
        "sources": [
            {
                "name": item.name,
                "success": item.success,
                "rules": len(item.rules),
                "issues": [issue.message for issue in item.issues],
            }
            for item in result.source_results
        ],
        "issues": [
            {
                "level": issue.level,
                "message": issue.message,
            }
            for issue in result.issues
        ],
    }

    import json

    report_path.write_text(
        json.dumps(
            report_data,
            ensure_ascii=False,
            indent=2,
        ),
        encoding="utf-8",
    )

    result.report = report_path

    result.success = True

    return result


# ============================================================
# Pipeline
# ============================================================


def run_pipeline(
    config: AppConfig,
) -> PipelineResult:

    pipeline_result = PipelineResult(
        success=True,
    )

    for group in enabled_groups(config):
        result = build_group(group)

        pipeline_result.groups.append(result)

        if not result.success:
            pipeline_result.success = False

    return pipeline_result


# ============================================================
# Summary
# ============================================================


def pipeline_summary(
    result: PipelineResult,
) -> str:

    lines = [
        "=== Pipeline Summary ===",
        (f"success: {result.success}"),
    ]

    for group in result.groups:
        lines.append(
            f"- {group.name}: "
            f"{'OK' if group.success else 'FAIL'} "
            f"rules={len(group.rules)}"
        )

    return "\n".join(lines)
