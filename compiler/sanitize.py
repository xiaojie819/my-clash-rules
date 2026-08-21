from __future__ import annotations

from dataclasses import dataclass, field

# ============================================================
# 统计
# ============================================================


@dataclass(slots=True)
class SanitizeStats:
    """
    文本清洗统计。
    """

    original_length: int = 0

    cleaned_length: int = 0

    removed_count: int = 0

    removed_chars: dict[str, int] = field(default_factory=dict)


@dataclass(slots=True)
class SanitizeResult:
    """
    清洗结果。
    """

    text: str

    stats: SanitizeStats


# ============================================================
# 不可见字符
# ============================================================

ZERO_WIDTH_CHARS = {
    "\u200b": "ZERO_WIDTH_SPACE",
    "\u200c": "ZERO_WIDTH_NON_JOINER",
    "\u200d": "ZERO_WIDTH_JOINER",
    "\ufeff": "BYTE_ORDER_MARK",
}


# ============================================================
# 清理函数
# ============================================================


def sanitize_text(
    text: str,
) -> SanitizeResult:
    """
    清洗规则源文本。

    处理：

    1. BOM
    2. 零宽字符
    3. 非法控制字符
    4. 换行统一

    不修改：
    - 英文
    - 中文
    - IP
    - 域名
    - YAML符号
    """

    stats = SanitizeStats(original_length=len(text))

    output: list[str] = []

    for char in text:
        # --------------------------------
        # 零宽字符
        # --------------------------------

        if char in ZERO_WIDTH_CHARS:
            stats.removed_count += 1

            name = ZERO_WIDTH_CHARS[char]

            stats.removed_chars[name] = (
                stats.removed_chars.get(
                    name,
                    0,
                )
                + 1
            )

            continue

        # --------------------------------
        # ASCII 控制字符
        #
        # 保留：
        # \n
        # \r
        # \t
        #
        # 删除：
        # 0x00-0x08
        # 0x0b
        # 0x0c
        # 0x0e-0x1f
        # --------------------------------

        code = ord(char)

        if code < 32:
            if char in (
                "\n",
                "\r",
                "\t",
            ):
                output.append(char)

                continue

            stats.removed_count += 1

            name = f"CONTROL_{code:02X}"

            stats.removed_chars[name] = (
                stats.removed_chars.get(
                    name,
                    0,
                )
                + 1
            )

            continue

        output.append(char)

    cleaned = "".join(output)

    # ------------------------------------
    # 统一换行
    # ------------------------------------

    cleaned = cleaned.replace(
        "\r\n",
        "\n",
    ).replace(
        "\r",
        "\n",
    )

    stats.cleaned_length = len(cleaned)

    return SanitizeResult(
        text=cleaned,
        stats=stats,
    )


# ============================================================
# 辅助
# ============================================================


def sanitize_summary(
    result: SanitizeResult,
) -> dict[str, object]:

    return {
        "original_length": (result.stats.original_length),
        "cleaned_length": (result.stats.cleaned_length),
        "removed_count": (result.stats.removed_count),
        "removed_chars": (result.stats.removed_chars),
    }
