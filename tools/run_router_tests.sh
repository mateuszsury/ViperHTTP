#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"

"$PYTHON" "$ROOT/tools/gen_router_vectors.py"

ROUTER_SRC=""
if [[ -f "$ROOT/cmodules/viperhttp/viperhttp/core/vhttp_router.c" ]]; then
  ROUTER_SRC="$ROOT/cmodules/viperhttp/viperhttp/core/vhttp_router.c"
elif [[ -f "$ROOT/src/vhttp_router.c" ]]; then
  ROUTER_SRC="$ROOT/src/vhttp_router.c"
fi

if [[ -z "$ROUTER_SRC" ]]; then
  echo "Router source not found. Implement vhttp_router.c before running tests." >&2
  exit 2
fi

OUT="$ROOT/tests/host/router_test"

cc -std=c11 -Wall -Wextra -Werror   -I"$ROOT/cmodules/viperhttp/viperhttp/core"   "$ROOT/tests/host/router_test.c" "$ROUTER_SRC"   -o "$OUT"

"$OUT"
