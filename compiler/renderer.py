from __future__ import annotations

import json

from .models import Rule


def _yaml_quote(
    value: str,
) -> str:
    """
    YAML字符串安全输出。
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
    生成 Clash/Mihomo classical payload YAML。
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


    lines.append(
        "payload:"
    )


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


    return "\n".join(lines) + "\n"
