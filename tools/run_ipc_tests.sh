#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

OUT="$ROOT/tests/host/ipc_test"

cc -std=c11 -Wall -Wextra -Werror   -I"$ROOT/cmodules/viperhttp/viperhttp/core"   "$ROOT/tests/host/ipc_test.c"   "$ROOT/cmodules/viperhttp/viperhttp/core/vhttp_ipc.c"   -o "$OUT"

"$OUT"
