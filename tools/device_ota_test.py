try:
    import ubinascii as binascii
except Exception:
    import binascii

try:
    import uhashlib as hashlib
except Exception:
    import hashlib

import viperhttp_ota as ota


def _require(cond, msg):
    if not cond:
        raise AssertionError(msg)


def _sha256_hex(data):
    ctx = hashlib.sha256()
    ctx.update(data)
    return binascii.hexlify(ctx.digest()).decode("utf-8")


status0 = ota.ota_status()
_require(status0.get("supported") is True, "ota unsupported on device")
running0 = (status0.get("running_partition") or {}).get("label")
next0 = (status0.get("next_update_partition") or {}).get("label")
if running0 is not None and next0 is not None and str(running0) == str(next0):
    print("SKIP: OTA device test requires baseline with distinct next_update partition")
    raise SystemExit(0)
if status0.get("active"):
    ota.ota_abort()

payload = b"OTA_DEVICE_TEST_PAYLOAD_1234567890"
digest = _sha256_hex(payload)

start = ota.ota_begin(expected_size=len(payload), expected_sha256=digest, force=True)
_require(start.get("active") is True, "ota_begin did not activate session")

ota.ota_write(payload[:11])
mid = ota.ota_write(payload[11:])
session_mid = mid.get("session") or {}
_require(session_mid.get("written_bytes") == len(payload), "written_bytes mismatch after chunk writes")

final = ota.ota_finalize(set_boot=False, reboot=False, strict_size=True)
_require(final.get("ok") is True, "ota_finalize failed")
_require(final.get("set_boot") is False, "set_boot should remain False in smoke test")
_require(final.get("written_bytes") == len(payload), "final written_bytes mismatch")

status1 = ota.ota_status()
_require(status1.get("active") is False, "session should be inactive after finalize")

ota.ota_begin(expected_size=4, force=True)
ota.ota_write(b"ab")
failed = False
try:
    ota.ota_finalize(set_boot=False, reboot=False, strict_size=True)
except Exception:
    failed = True
_require(failed, "strict_size finalize should fail for partial image")
ota.ota_abort()

print("PASS: OTA device test")
