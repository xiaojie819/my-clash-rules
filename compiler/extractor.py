from __future__ import annotations

from compiler.models import ParseResult, SourceFormat
from compiler.parsers import parse_rules


def extract_rules(
    text: str,
    source,
    *,
    format_hint: SourceFormat | None = None,
) -> ParseResult:
    """
    统一解析入口。

    extractor 不负责规则解析。
    所有格式识别、规则转换统一交给 parser。
    """

    return parse_rules(
        text,
        source=source,
        format_hint=format_hint,
    )
