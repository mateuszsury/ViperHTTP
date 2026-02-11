#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
ROOT_DIR=$(cd "$SCRIPT_DIR/.." && pwd)
MICROPY_DIR="$ROOT_DIR/vendor/micropython"
BOARD="ESP32S3_N16R8"
USER_C_MODULES="$ROOT_DIR/cmodules/viperhttp"
DEFAULT_IDF_PATH="$HOME/esp-idf-5.5.1"
DEFAULT_IDF_TOOLS_PATH="$HOME/.espressif-viperhttp"
DEFAULT_IDF_PY_ENV_PATH="$DEFAULT_IDF_TOOLS_PATH/python_env"
DEFAULT_IDF_TARGET="esp32s3"

if [[ ! -d "$MICROPY_DIR" ]]; then
  echo "[ERROR] MicroPython repo not found at $MICROPY_DIR" >&2
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

if [[ -z "${IDF_TARGET:-}" ]]; then
  export IDF_TARGET="$DEFAULT_IDF_TARGET"
fi

if ! command -v idf.py >/dev/null 2>&1; then
  if [[ -n "${IDF_PATH:-}" && -f "$IDF_PATH/export.sh" ]]; then
    # Provide libusb from a user-local extract if system libusb isn't installed.
    export LD_LIBRARY_PATH="$HOME/.local/libusb/usr/lib/x86_64-linux-gnu:${LD_LIBRARY_PATH:-}"
    # shellcheck source=/dev/null
    source "$IDF_PATH/export.sh" >/dev/null 2>&1 || true
  fi
fi

if ! command -v idf.py >/dev/null 2>&1; then
  echo "[ERROR] idf.py not found in PATH. Install ESP-IDF in WSL and export PATH." >&2
  exit 1
fi

if ! idf.py --version >/dev/null 2>&1; then
  echo "[ERROR] idf.py is not runnable. Ensure ESP-IDF is installed inside WSL." >&2
  exit 1
fi

# Prevent collisions when another build uses the same toolchain or Python env.
if command -v flock >/dev/null 2>&1; then
  LOCK_FILE="$IDF_TOOLS_PATH/.viperhttp-build.lock"
  exec 9>"$LOCK_FILE"
  if ! flock -n 9; then
    echo "[ERROR] Another ViperHTTP build is running using $IDF_TOOLS_PATH." >&2
    echo "Close the other build or remove $LOCK_FILE if it is stale." >&2
    exit 1
  fi
fi

ensure_kconfig_bool() {
  local file="$1"
  local symbol="$2"
  local value="$3"
  local yes_line="${symbol}=y"
  local no_line="# ${symbol} is not set"
  if [[ ! -f "$file" ]]; then
    return 0
  fi
  if [[ "$value" == "y" ]]; then
    if grep -q "^${symbol}=y$" "$file"; then
      return 0
    fi
    if grep -q "^# ${symbol} is not set$" "$file"; then
      sed -i "s|^# ${symbol} is not set$|${yes_line}|" "$file"
      return 0
    fi
    if grep -q "^${symbol}=n$" "$file"; then
      sed -i "s|^${symbol}=n$|${yes_line}|" "$file"
      return 0
    fi
    echo "${yes_line}" >>"$file"
    return 0
  fi
  if grep -q "^# ${symbol} is not set$" "$file"; then
    return 0
  fi
  if grep -q "^${symbol}=y$" "$file"; then
    sed -i "s|^${symbol}=y$|${no_line}|" "$file"
    return 0
  fi
  if grep -q "^${symbol}=n$" "$file"; then
    sed -i "s|^${symbol}=n$|${no_line}|" "$file"
    return 0
  fi
  echo "${no_line}" >>"$file"
}

make -C "$MICROPY_DIR/mpy-cross"
make -C "$MICROPY_DIR/ports/esp32" submodules BOARD="$BOARD"

BUILD_DIR="$MICROPY_DIR/ports/esp32/build-$BOARD"
ensure_kconfig_bool "$BUILD_DIR/submodules/sdkconfig" "CONFIG_MBEDTLS_SSL_ALPN" "y"
ensure_kconfig_bool "$BUILD_DIR/sdkconfig" "CONFIG_MBEDTLS_SSL_ALPN" "y"

make -C "$MICROPY_DIR/ports/esp32" BOARD="$BOARD" USER_C_MODULES="$USER_C_MODULES"

echo "[OK] Build complete. Firmware is under: $MICROPY_DIR/ports/esp32/build-$BOARD/"
