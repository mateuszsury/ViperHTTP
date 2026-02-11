#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PYTHON="${PYTHON:-python3}"

"$PYTHON" "$ROOT/tools/gen_parser_vectors.py"

PARSER_SRC=""
if [[ -f "$ROOT/cmodules/viperhttp/viperhttp/core/vhttp_parser.c" ]]; then
  PARSER_SRC="$ROOT/cmodules/viperhttp/viperhttp/core/vhttp_parser.c"
elif [[ -f "$ROOT/src/vhttp_parser.c" ]]; then
  PARSER_SRC="$ROOT/src/vhttp_parser.c"
fi

if [[ -z "$PARSER_SRC" ]]; then
  echo "Parser source not found. Implement vhttp_parse_request() before running tests." >&2
  exit 2
fi

OUT="$ROOT/tests/host/parser_test"

cc -std=c11 -Wall -Wextra -Werror   -I"$ROOT/cmodules/viperhttp/viperhttp/core"   "$ROOT/tests/host/parser_test.c" "$PARSER_SRC"   -o "$OUT"

"$OUT"
