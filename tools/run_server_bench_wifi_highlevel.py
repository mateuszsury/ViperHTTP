import gc
import network
import time

import bench_server_highlevel as bench_runtime

SSID = "STAR1"
PASSWORD = "wodasodowa"
WIFI_TIMEOUT_MS = 20000
WIFI_RETRIES = 4


def _has_valid_ip(wlan):
    try:
        ip_addr = wlan.ifconfig()[0]
    except Exception:
        return False
    return bool(ip_addr and ip_addr != "0.0.0.0")


def _tune_wifi_power_save(wlan):
    try:
        pm_none = getattr(network.WLAN, "PM_NONE", None)
        if pm_none is not None:
            wlan.config(pm=pm_none)
        else:
            wlan.config(pm=0)
    except Exception as exc:
        print("wifi_pm_config_error", repr(exc))


def connect_wifi(ssid, password, timeout_ms=WIFI_TIMEOUT_MS):
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    _tune_wifi_power_save(wlan)
    last_exc = None

    for _ in range(WIFI_RETRIES):
        gc.collect()
        try:
            try:
                wlan.disconnect()
            except Exception:
                pass
            time.sleep_ms(150)
            wlan.connect(ssid, password)
            start = time.ticks_ms()
            while time.ticks_diff(time.ticks_ms(), start) < timeout_ms:
                if wlan.isconnected() and _has_valid_ip(wlan):
                    return wlan, True
                time.sleep_ms(200)
            if wlan.isconnected() and _has_valid_ip(wlan):
                return wlan, True
        except Exception as exc:
            last_exc = exc
        time.sleep_ms(300)

    if last_exc is not None:
        raise last_exc
    return wlan, False


wlan, ok = connect_wifi(SSID, PASSWORD)
print("wifi_connected", ok)
print("ifconfig", wlan.ifconfig())
if not ok:
    raise RuntimeError("wifi connection failed")


def _wifi_status():
    return wlan.isconnected(), wlan.ifconfig()


bench_runtime.start_benchmark_app(wlan.ifconfig()[0], _wifi_status, "wifi")
