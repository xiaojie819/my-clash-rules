from pathlib import Path

import yaml


def validate_rule_file(path: Path) -> None:
    data = yaml.safe_load(path.read_text(encoding="utf-8"))

    assert isinstance(data, dict)
    assert "payload" in data
    assert isinstance(data["payload"], list)
    assert len(data["payload"]) > 0

    print(
        path,
        "OK",
        "rules=",
        len(data["payload"]),
    )


for path in Path("rules").glob("*.yaml"):
    validate_rule_file(path)
