from __future__ import annotations

import urllib.error
import urllib.request

DEFAULT_USER_AGENT = "my-clash-rules/1.0 (universal-rule-compiler)"


def fetch_url_text(
    url: str,
    *,
    timeout: int = 30,
    user_agent: str = DEFAULT_USER_AGENT,
) -> str:

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": user_agent,
        },
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=timeout,
        ) as response:
            data = response.read()

    except urllib.error.URLError as exc:
        raise RuntimeError(f"下载失败: {url}: {exc}") from exc

    return data.decode(
        "utf-8",
        errors="replace",
    )
