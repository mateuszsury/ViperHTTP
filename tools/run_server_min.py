import time
import network
import uasyncio as asyncio
import viperhttp
import viperhttp_app as appmod
import viperhttp_bridge as bridge

SSID = "STAR1"
PASSWORD = "wodasodowa"


def connect_wifi(timeout_ms=20000):
    wlan = network.WLAN(network.STA_IF)
    wlan.active(True)
    try:
        wlan.disconnect()
    except Exception:
        pass
    wlan.connect(SSID, PASSWORD)
    start = time.ticks_ms()
    while time.ticks_diff(time.ticks_ms(), start) < timeout_ms:
        if wlan.isconnected():
            ip = wlan.ifconfig()[0]
            if ip and ip != "0.0.0.0":
                return wlan
        time.sleep_ms(200)
    raise RuntimeError("wifi connection failed")


wlan = connect_wifi()
print("wifi_connected", True)
print("ifconfig", wlan.ifconfig())
try:
    from viperhttp import middleware as _mw
    ip_addr = wlan.ifconfig()[0]
    appmod.app.add_middleware(
        _mw.TrustedHostMiddleware,
        allowed_hosts=[ip_addr, "localhost", "127.0.0.1"],
    )
except Exception:
    pass
try:
    viperhttp.stop()
except Exception:
    pass
bridge.run(appmod.app, port=8080, wifi=False)
print("server_running", viperhttp.is_running())
asyncio.get_event_loop().run_forever()
