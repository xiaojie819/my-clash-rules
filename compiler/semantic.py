from __future__ import annotations

from urllib.parse import urlparse


INTENT_KEYWORDS = {
    "proxy": (
        "proxy",
        "proxied",
        "gfw",
        "telegram",
        "google",
        "youtube",
        "github",
        "global",
    ),
    "direct": (
        "direct",
        "china",
        "cn",
        "lan",
        "local",
    ),
    "reject": (
        "reject",
        "block",
        "ad",
        "advertising",
        "privacy",
    ),
}


def infer_intent(
    *,
    name: str,
    url: str = "",
    current: str = "unknown",
) -> str:
    if current and current != "unknown":
        return current

    target = " ".join(
        [
            name.lower(),
            urlparse(url).path.lower(),
            url.lower(),
        ]
    )

    for intent, keywords in INTENT_KEYWORDS.items():
        for keyword in keywords:
            if keyword in target:
                return intent

    return "unknown"
