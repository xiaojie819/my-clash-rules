#!/usr/bin/env bash

set -e

echo "================================"
echo "  Full Rule Source Check"
echo "================================"

echo
echo "=== 1. Git Status ==="
git status --short

echo
echo "=== 2. Environment ==="
python --version

echo
echo "=== 3. Ruff ==="
ruff check .

echo
echo "=== 4. Tests ==="
pytest

echo
echo "=== 5. Build ==="
python main.py build

echo
echo "=== 6. Validate Output ==="
python scripts/validate_rules.py

echo
echo "=== 7. Output Files ==="
find rules -name "*.yaml" -type f

echo
echo "=== 8. YAML Payload Check ==="
python - <<'PY'
from pathlib import Path
import yaml

for p in Path("rules").glob("*.yaml"):
    data = yaml.safe_load(
        p.read_text(encoding="utf-8")
    )

    assert isinstance(data, dict), p
    assert "payload" in data, p
    assert isinstance(data["payload"], list), p
    assert len(data["payload"]) > 0, p

    print(
        p,
        "OK",
        "rules=",
        len(data["payload"])
    )
PY

echo
echo "=== 9. Workflow ==="
if [ -f ".github/workflows/build.yml" ]; then
    echo "workflow OK"
else
    echo "workflow missing"
fi

echo
echo "================================"
echo "  ALL CHECK FINISHED"
echo "================================"
