import gc
import time
import uasyncio as asyncio

import network
from machine import Pin, SPI

import viperhttp

PORT = 8080
SERVER_LOG_LEVEL = "warn"

SPI_ID = 1
PIN_SCK = 12
PIN_MOSI = 13
PIN_MISO = 14
PIN_CS = 10
PIN_INT = 11
PIN_RST = 15
PHY_ADDR = 0

SERVER_MIN_WORKERS = None
SERVER_MAX_WORKERS = None
BRIDGE_MIN_WORKERS = 4
BRIDGE_MAX_WORKERS = 8
BRIDGE_QUEUE_SIZE = 64
BRIDGE_AUTOSCALE = True
BRIDGE_ENQUEUE_WAIT_MS = 12
BRIDGE_WORKER_YIELD_EVERY = 8
BRIDGE_SCALE_UP_MAX_BURST = 8

# Optional static fallback when link is up but DHCP is unavailable.
# Example:
# STATIC_IPV4 = ("192.168.0.209", "255.255.255.0", "192.168.0.1", "8.8.8.8")
STATIC_IPV4 = ("192.168.0.209", "255.255.255.0", "192.168.0.1", "8.8.8.8")

# Keep hardware objects alive for runtime lifetime.
_ETH_SPI_OBJ = None
_ETH_CS_PIN = None


def _w5500_read_reg(spi, cs_pin, addr, block=0x00):
    ctrl = ((block & 0x1F) << 3) | 0x00  # read, variable length mode
    hdr = bytes([(addr >> 8) & 0xFF, addr & 0xFF, ctrl])
    b = bytearray(1)
    cs_pin.off()
    try:
        spi.write(hdr)
        spi.readinto(b)
    finally:
        cs_pin.on()
    return b[0]


def _w5500_probe(spi, cs_pin):
    # VERSIONR=0x0039 should be 0x04 for W5500.
    ver = _w5500_read_reg(spi, cs_pin, 0x0039, 0x00)
    # PHYCFGR=0x002E, bit0 is link status.
    phycfg = _w5500_read_reg(spi, cs_pin, 0x002E, 0x00)
    return ver, phycfg


def _w5500_link_up(phycfg):
    return bool(phycfg & 0x01)


def _wait_eth_ready(lan, timeout_ms=8000):
    start = time.ticks_ms()
    while time.ticks_diff(time.ticks_ms(), start) < timeout_ms:
        try:
            if lan.isconnected():
                cfg = lan.ifconfig()
                if cfg[0] and cfg[0] != "0.0.0.0":
                    return True
        except Exception:
            pass
        time.sleep_ms(200)
    return False


def connect_eth(timeout_ms=20000):
    global _ETH_SPI_OBJ
    global _ETH_CS_PIN

    _ETH_SPI_OBJ = SPI(SPI_ID, sck=Pin(PIN_SCK), mosi=Pin(PIN_MOSI), miso=Pin(PIN_MISO))
    _ETH_CS_PIN = Pin(PIN_CS, Pin.OUT, value=1)
    try:
        ver, phycfg = _w5500_probe(_ETH_SPI_OBJ, _ETH_CS_PIN)
        print("w5500_probe", "version", ver, "phycfg", phycfg, "link", _w5500_link_up(phycfg))
    except Exception as exc:
        return None, False, "w5500_probe_error: " + repr(exc)

    if ver != 0x04:
        return None, False, "w5500_signature_invalid"

    lan = network.LAN(
        spi=_ETH_SPI_OBJ,
        phy_type=network.PHY_W5500,
        phy_addr=PHY_ADDR,
        cs=_ETH_CS_PIN,
        int=Pin(PIN_INT),
        reset=Pin(PIN_RST),
    )
    lan.active(True)
    try:
        lan.ipconfig(dhcp4=True)
    except Exception:
        try:
            lan.ifconfig("dhcp")
        except Exception:
            pass

    start = time.ticks_ms()
    link_seen = False
    while time.ticks_diff(time.ticks_ms(), start) < timeout_ms:
        cfg = lan.ifconfig()
        ip = cfg[0]
        if ip and ip != "0.0.0.0":
            _wait_eth_ready(lan, timeout_ms=2000)
            return lan, True, "dhcp_or_static_ip"
        try:
            cur_phycfg = _w5500_read_reg(_ETH_SPI_OBJ, _ETH_CS_PIN, 0x002E, 0x00)
            if _w5500_link_up(cur_phycfg):
                link_seen = True
        except Exception:
            pass
        time.sleep_ms(200)

    if link_seen and STATIC_IPV4:
        try:
            lan.ifconfig(STATIC_IPV4)
            cfg = lan.ifconfig()
            if cfg[0] and cfg[0] != "0.0.0.0":
                _wait_eth_ready(lan, timeout_ms=8000)
                return lan, True, "static_fallback"
        except Exception as exc:
            return lan, False, "static_fallback_error: " + repr(exc)
        return lan, False, "static_fallback_failed"

    if not link_seen:
        return lan, False, "phy_link_down"
    return lan, False, "dhcp_timeout"


def start_bridge(app):
    try:
        viperhttp.stop()
    except Exception:
        pass
    time.sleep_ms(150)
    gc.collect()
    bridge.run(
        app,
        port=PORT,
        wifi=False,
        https=False,
        http2=False,
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
    return viperhttp.is_running()


lan, ok, reason = connect_eth()
print("eth_connected", ok)
print("eth_reason", reason)
print("ifconfig", lan.ifconfig())
if not ok:
    raise RuntimeError("ethernet connection failed")

import viperhttp_app as appmod
import viperhttp_bridge as bridge

try:
    viperhttp.set_log_level(SERVER_LOG_LEVEL)
    print("vhttp_log_level", viperhttp.get_log_level())
except Exception as exc:
    print("vhttp_log_level_error", repr(exc))

try:
    from viperhttp import middleware as _mw
    ip_addr = lan.ifconfig()[0]
    allowed_hosts = [ip_addr, "localhost", "127.0.0.1", ip_addr + ":" + str(PORT)]
    appmod.app.add_middleware(_mw.TrustedHostMiddleware, allowed_hosts=allowed_hosts)
except Exception:
    pass

if not start_bridge(appmod.app):
    raise RuntimeError("server start failed")
print("server_running", viperhttp.is_running())


async def status_loop():
    while True:
        print("eth_status", lan.isconnected(), lan.ifconfig())
        await asyncio.sleep(10)


asyncio.get_event_loop().create_task(status_loop())
asyncio.get_event_loop().run_forever()
