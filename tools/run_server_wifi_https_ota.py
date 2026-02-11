import time
import network
import gc
import uasyncio as asyncio
import viperhttp

SSID = "STAR1"
PASSWORD = "wodasodowa"
WIFI_TIMEOUT_MS = 20000
SERVER_START_RETRIES = 4
SERVER_LOG_LEVEL = "warn"

SERVER_MIN_WORKERS = None
SERVER_MAX_WORKERS = None
BRIDGE_MIN_WORKERS = 4
BRIDGE_MAX_WORKERS = 8
BRIDGE_QUEUE_SIZE = 64
BRIDGE_AUTOSCALE = True
BRIDGE_ENQUEUE_WAIT_MS = 12
BRIDGE_WORKER_YIELD_EVERY = 8
BRIDGE_SCALE_UP_MAX_BURST = 8

TLS_CERT_PATH = "/certs/server.crt"
TLS_KEY_PATH = "/certs/server.key"
HTTP2_ENABLED = True
HTTP2_MAX_STREAMS = 8

OTA_ENABLED = True
OTA_PREFIX = "/ota"
OTA_TOKEN = "ota-e2e-token"
OTA_TOKEN_HEADER = "X-OTA-Token"
OTA_TOKEN_QUERY = "token"


def has_valid_ip(wlan):
    try:
        ip_addr = wlan.ifconfig()[0]
    except Exception:
        return False
    return bool(ip_addr and ip_addr != "0.0.0.0")


def tune_wifi_power_save(wlan):
    try:
        pm_none = getattr(network.WLAN, "PM_NONE", None)
    except Exception:
        pm_none = None
    try:
        if pm_none is not None:
            wlan.config(pm=pm_none)
        else:
            wlan.config(pm=0)
    except Exception as exc:
        print("wifi_pm_config_error", repr(exc))
        return
    try:
        print("wifi_pm", wlan.config("pm"))
    except Exception:
        print("wifi_pm_set")


def connect_wifi(ssid, password, timeout_ms=15000):
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    tune_wifi_power_save(wlan)
    last_exc = None
    for _ in range(4):
        gc.collect()
        try:
            time.sleep_ms(200)
            try:
                wlan.disconnect()
            except Exception:
                pass
            wlan.connect(ssid, password)
            start = time.ticks_ms()
            while True:
                if wlan.isconnected() and has_valid_ip(wlan):
                    return wlan, True
                if time.ticks_diff(time.ticks_ms(), start) > timeout_ms:
                    break
                time.sleep_ms(200)
            if wlan.isconnected() and has_valid_ip(wlan):
                return wlan, True
        except Exception as exc:
            last_exc = exc
        gc.collect()
        time.sleep_ms(500)
    if last_exc:
        raise last_exc
    return wlan, False


def start_bridge_with_retry(app, port=8080):
    last_exc = None
    for attempt in range(SERVER_START_RETRIES):
        try:
            viperhttp.stop()
        except Exception:
            pass
        time.sleep_ms(150)
        gc.collect()
        try:
            bridge.run(
                app,
                port=port,
                wifi=False,
                https=True,
                http2=HTTP2_ENABLED,
                http2_max_streams=HTTP2_MAX_STREAMS,
                tls_cert_path=TLS_CERT_PATH,
                tls_key_path=TLS_KEY_PATH,
                ota=OTA_ENABLED,
                ota_prefix=OTA_PREFIX,
                ota_token=OTA_TOKEN,
                ota_token_header=OTA_TOKEN_HEADER,
                ota_token_query=OTA_TOKEN_QUERY,
                min_workers=SERVER_MIN_WORKERS,
                max_workers=SERVER_MAX_WORKERS,
                bridge_min_workers=BRIDGE_MIN_WORKERS,
                bridge_max_workers=BRIDGE_MAX_WORKERS,
                bridge_queue_size=BRIDGE_QUEUE_SIZE,
                bridge_autoscale=BRIDGE_AUTOSCALE,
                bridge_enqueue_wait_ms=BRIDGE_ENQUEUE_WAIT_MS,
                bridge_worker_yield_every=BRIDGE_WORKER_YIELD_EVERY,
                bridge_scale_up_max_burst=BRIDGE_SCALE_UP_MAX_BURST,
            )
            if viperhttp.is_running():
                return True
        except Exception as exc:
            last_exc = exc
            print("bridge_start_retry", attempt + 1, repr(exc))
        time.sleep_ms(300)
    if last_exc:
        raise last_exc
    return False


wlan, ok = connect_wifi(SSID, PASSWORD, timeout_ms=WIFI_TIMEOUT_MS)
print("wifi_connected", ok)
print("ifconfig", wlan.ifconfig())
if not ok or not has_valid_ip(wlan):
    raise RuntimeError("wifi connection failed")

gc.collect()
import viperhttp_app as appmod
import viperhttp_bridge as bridge

try:
    viperhttp.set_log_level(SERVER_LOG_LEVEL)
    print("vhttp_log_level", viperhttp.get_log_level())
except Exception as exc:
    print("vhttp_log_level_error", repr(exc))

try:
    from viperhttp import middleware as _mw
    ip_addr = wlan.ifconfig()[0]
    allowed_hosts = [ip_addr, "localhost", "127.0.0.1"]
    allowed_hosts.append("%s:8080" % ip_addr)
    allowed_hosts.append("localhost:8080")
    allowed_hosts.append("127.0.0.1:8080")
    appmod.app.add_middleware(
        _mw.TrustedHostMiddleware,
        allowed_hosts=allowed_hosts,
    )
except Exception:
    pass

if not start_bridge_with_retry(appmod.app, port=8080):
    raise RuntimeError("server start failed")
print("server_running", viperhttp.is_running())
try:
    print("https_status", viperhttp.https_status())
except Exception as exc:
    print("https_status_error", repr(exc))
try:
    print("http2_status", viperhttp.http2_status())
except Exception as exc:
    print("http2_status_error", repr(exc))


async def status_loop():
    while True:
        if not wlan.isconnected() or not has_valid_ip(wlan):
            print("wifi_reconnect_begin")
            try:
                _wlan, _ok = connect_wifi(SSID, PASSWORD, timeout_ms=WIFI_TIMEOUT_MS)
                if _ok:
                    print("wifi_reconnect_ok", _wlan.ifconfig())
            except Exception as exc:
                print("wifi_reconnect_error", repr(exc))
        print("wifi_status", wlan.isconnected(), wlan.ifconfig())
        await asyncio.sleep(10)


asyncio.get_event_loop().create_task(status_loop())
asyncio.get_event_loop().run_forever()
