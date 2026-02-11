import gc
import network
import time
from machine import Pin, SPI

import bench_server_highlevel as bench_runtime

SPI_ID = 1
PIN_SCK = 12
PIN_MOSI = 13
PIN_MISO = 14
PIN_CS = 10
PIN_INT = 11
PIN_RST = 15
PHY_ADDR = 0
ETH_TIMEOUT_MS = 20000

# Optional static fallback if DHCP is unavailable.
STATIC_IPV4 = ("192.168.0.209", "255.255.255.0", "192.168.0.1", "8.8.8.8")

_ETH_SPI_OBJ = None
_ETH_CS_PIN = None


def _w5500_read_reg(spi, cs_pin, addr, block=0x00):
    ctrl = ((block & 0x1F) << 3) | 0x00
    hdr = bytes([(addr >> 8) & 0xFF, addr & 0xFF, ctrl])
    value = bytearray(1)
    cs_pin.off()
    try:
        spi.write(hdr)
        spi.readinto(value)
    finally:
        cs_pin.on()
    return value[0]


def _w5500_probe(spi, cs_pin):
    version = _w5500_read_reg(spi, cs_pin, 0x0039, 0x00)
    phycfg = _w5500_read_reg(spi, cs_pin, 0x002E, 0x00)
    return version, phycfg


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


def connect_eth(timeout_ms=ETH_TIMEOUT_MS):
    global _ETH_SPI_OBJ
    global _ETH_CS_PIN

    gc.collect()
    _ETH_SPI_OBJ = SPI(SPI_ID, sck=Pin(PIN_SCK), mosi=Pin(PIN_MOSI), miso=Pin(PIN_MISO))
    _ETH_CS_PIN = Pin(PIN_CS, Pin.OUT, value=1)

    version, phycfg = _w5500_probe(_ETH_SPI_OBJ, _ETH_CS_PIN)
    print("w5500_probe", "version", version, "phycfg", phycfg, "link", _w5500_link_up(phycfg))
    if version != 0x04:
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
                _wait_eth_ready(lan, timeout_ms=4000)
                return lan, True, "static_fallback"
        except Exception as exc:
            return lan, False, "static_fallback_error: " + repr(exc)
        return lan, False, "static_fallback_failed"

    if not link_seen:
        return lan, False, "phy_link_down"
    return lan, False, "dhcp_timeout"


lan, ok, reason = connect_eth()
print("eth_connected", ok)
print("eth_reason", reason)
print("ifconfig", lan.ifconfig() if lan else None)
if not ok:
    raise RuntimeError("ethernet connection failed")


def _eth_status():
    return lan.isconnected(), lan.ifconfig()


bench_runtime.start_benchmark_app(lan.ifconfig()[0], _eth_status, "ethernet")
