#!/usr/bin/env bash

set -e

echo "================================"
echo "  Project Diagnostic Check"
echo "================================"

echo
echo "=== Git Status ==="
git status --short

echo
echo "=== Python Version ==="
python --version

echo
echo "=== Ruff ==="
ruff check .

echo
echo "=== Pytest ==="
pytest

echo
echo "=== Build ==="
python main.py build

echo
echo "=== Generated Files ==="
find rules -maxdepth 1 -type f 2>/dev/null || true

echo
echo "=== Workflow ==="
test -f .github/workflows/build.yml \
    && echo "workflow ok" \
    || echo "workflow missing"

echo
echo "================================"
echo "  Diagnostic Finished"
echo "================================"
