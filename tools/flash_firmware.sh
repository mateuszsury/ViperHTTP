#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
  echo "Usage: $0 <serial-port>" >&2
  echo "Example: $0 /dev/ttyUSB0" >&2
  exit 1
fi

PORT="$1"
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
BUILD_DIR="$ROOT_DIR/vendor/micropython/ports/esp32/build-ESP32S3_N16R8"
DEFAULT_IDF_PATH="$HOME/esp-idf-5.5.1"
DEFAULT_IDF_TOOLS_PATH="$HOME/.espressif-viperhttp"
DEFAULT_IDF_PY_ENV_PATH="$DEFAULT_IDF_TOOLS_PATH/python_env"

if [[ ! -d "$BUILD_DIR" ]]; then
  echo "[ERROR] Build directory not found: $BUILD_DIR" >&2
  exit 1
fi

if [[ -z "${IDF_PATH:-}" ]]; then
  if [[ -d "$DEFAULT_IDF_PATH" ]]; then
    export IDF_PATH="$DEFAULT_IDF_PATH"
  elif [[ -d "$HOME/esp-idf" ]]; then
    export IDF_PATH="$HOME/esp-idf"
  fi
fi

if [[ -z "${IDF_TOOLS_PATH:-}" ]]; then
  export IDF_TOOLS_PATH="$DEFAULT_IDF_TOOLS_PATH"
fi

if [[ -z "${IDF_PYTHON_ENV_PATH:-}" ]]; then
  export IDF_PYTHON_ENV_PATH="$DEFAULT_IDF_PY_ENV_PATH"
fi

export LD_LIBRARY_PATH="$HOME/.local/libusb/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
if [[ -n "${IDF_PATH:-}" && -f "$IDF_PATH/export.sh" ]]; then
  # shellcheck source=/dev/null
  source "$IDF_PATH/export.sh" >/dev/null 2>&1 || true
fi

if ! command -v python >/dev/null 2>&1; then
  echo "[ERROR] python not found in PATH." >&2
  exit 1
fi

if [[ ! -f "$BUILD_DIR/flash_args" ]]; then
  echo "[ERROR] flash_args not found. Build firmware first." >&2
  exit 1
fi

( cd "$BUILD_DIR" && python -m esptool --chip esp32s3 -b 460800 --before default_reset --after hard_reset -p "$PORT" write_flash "@flash_args" )
