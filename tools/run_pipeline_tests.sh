#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

OUT="$ROOT/tests/host/pipeline_test"

cc -std=c11 -Wall -Wextra -Werror   -I"$ROOT/cmodules/viperhttp/viperhttp/core"   "$ROOT/tests/host/pipeline_test.c"   "$ROOT/cmodules/viperhttp/viperhttp/core/vhttp_parser.c"   "$ROOT/cmodules/viperhttp/viperhttp/core/vhttp_router.c"   "$ROOT/cmodules/viperhttp/viperhttp/core/vhttp_connection.c"   "$ROOT/cmodules/viperhttp/viperhttp/core/vhttp_server.c"   -o "$OUT"

"$OUT"
