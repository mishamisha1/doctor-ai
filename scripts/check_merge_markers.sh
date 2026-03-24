#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

echo "Checking repository for unresolved merge markers..."
if rg -n "^(<<<<<<<|=======|>>>>>>>)" .; then
  echo
  echo "Found unresolved merge markers."
  exit 1
fi

echo "No unresolved merge markers found."
