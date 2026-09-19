#!/usr/bin/env bash
# Run what CI runs, in the same order. The one command before opening a PR.
set -euo pipefail
cd "$(dirname "$0")/.."

step() { printf '\n== %s\n' "$1"; }

step "Hygiene"
bash scripts/check-hygiene.sh

step "DCO sign-off on commits not yet on main"
base=$(git merge-base HEAD origin/main 2>/dev/null || git rev-list --max-parents=0 HEAD | tail -1)
missing=0
while IFS= read -r sha; do
  if ! git log -1 --format=%B "$sha" | grep -q '^Signed-off-by: .* <.*>'; then
    echo "missing Signed-off-by: $(git log -1 --format='%h %s' "$sha")"; missing=1
  fi
done < <(git rev-list "$base"..HEAD 2>/dev/null)
[ "$missing" -eq 0 ] && echo "DCO: all commits signed off" || exit 1

step "Tests"
if [ -x .venv/bin/python3 ]; then PY=.venv/bin/python3; else PY=python3; fi
if [ -f pyproject.toml ] || [ -f requirements.txt ] || ls tests/*.py >/dev/null 2>&1; then
  if ! "$PY" -c 'import pytest' 2>/dev/null; then
    python3 -m venv .venv && PY=.venv/bin/python3 && "$PY" -m pip install --quiet pytest
    [ -f requirements.txt ] && "$PY" -m pip install --quiet -r requirements.txt
  fi
  "$PY" -m pytest -q
else
  echo "no tests yet (add tests/ or pyproject.toml)"
fi

printf '\nAll gates green.\n'
