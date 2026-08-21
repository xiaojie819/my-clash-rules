#!/usr/bin/env bash

set -e

echo "================================"
echo "  Full Rule Source Fix"
echo "================================"

echo
echo "=== Ruff Auto Fix ==="
ruff check . --fix

echo
echo "=== Ruff Format ==="
ruff format .

echo
echo "=== Run Check ==="
./scripts/full_check.sh

echo
echo "================================"
echo "  Fix Finished"
echo "================================"
