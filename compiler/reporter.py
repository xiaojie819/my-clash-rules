from __future__ import annotations

import json
from pathlib import Path

from .build import BuildResult


def build_report_dict(
    result: BuildResult,
) -> dict[str, object]:
    """
    生成后续 reports/*.json 可用的数据。
    """

    stats = result.stats.as_dict() if result.stats else {}

    level_counts = {
        "error": 0,
        "warning": 0,
        "info": 0,
        "other": 0,
    }

    for issue in result.issues:
        level = issue.level.strip().lower()

        if level in level_counts:
            level_counts[level] += 1

        else:
            level_counts["other"] += 1

    return {
        "success": result.success,
        "detected_format": (result.detected_format.value),
        "output_mode": (result.output_mode.value),
        "optimize_mode": (result.optimize_mode.value),
        "final_rule_count": (result.final_rule_count),
        "issue_levels": (level_counts),
        "stats": stats,
        "issues": [
            {
                "level": issue.level,
                "message": issue.message,
                "raw": issue.raw,
                "source": (
                    issue.source.url
                    if (issue.source and issue.source.url)
                    else (
                        issue.source.file
                        if (issue.source and issue.source.file)
                        else ""
                    )
                ),
                "line_number": (issue.source.line_number if issue.source else None),
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

    output_path = Path(output_path)

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    data = build_report_dict(result)

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
