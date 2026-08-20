from __future__ import annotations

from pathlib import Path


def read_file_text(
    path: str | Path,
) -> str:
    path = Path(path)

    return path.read_text(
        encoding="utf-8",
        errors="replace",
    )
