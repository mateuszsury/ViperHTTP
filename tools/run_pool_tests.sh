#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

SRC=""
if [[ -f "$ROOT/cmodules/viperhttp/viperhttp/core/vhttp_connection.c" ]]; then
  SRC="$ROOT/cmodules/viperhttp/viperhttp/core/vhttp_connection.c"
elif [[ -f "$ROOT/src/vhttp_connection.c" ]]; then
  SRC="$ROOT/src/vhttp_connection.c"
fi

if [[ -z "$SRC" ]]; then
  echo "Connection source not found." >&2
  exit 2
fi

OUT="$ROOT/tests/host/pool_test"

cc -std=c11 -Wall -Wextra -Werror   -I"$ROOT/cmodules/viperhttp/viperhttp/core"   "$ROOT/tests/host/pool_test.c" "$SRC"   -o "$OUT"

"$OUT"
