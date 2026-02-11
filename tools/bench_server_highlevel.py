import uasyncio as asyncio
import viperhttp

PORT = 8080
SERVER_LOG_LEVEL = "warn"

# Keep runtime config identical across Wi-Fi and Ethernet benchmark runners.
SERVER_MIN_WORKERS = None
SERVER_MAX_WORKERS = None
BRIDGE_MIN_WORKERS = 4
BRIDGE_MAX_WORKERS = 8
BRIDGE_QUEUE_SIZE = 64
BRIDGE_POLL_BURST = 4
BRIDGE_IDLE_SLEEP_MS = 1
BRIDGE_AUTOSCALE = True
BRIDGE_ENQUEUE_WAIT_MS = 12
BRIDGE_WORKER_YIELD_EVERY = 8
BRIDGE_SCALE_UP_MAX_BURST = 8

HTTPS_ENABLED = False
HTTP2_ENABLED = False
HTTP2_MAX_STREAMS = 8


def _add_trusted_hosts(app, ip_addr):
    try:
        state = app.state if hasattr(app, "state") else {}
    except Exception:
        state = {}
    try:
        from viperhttp import middleware as _mw
    except Exception:
        return

    allowed_hosts = [
        ip_addr,
        "localhost",
        "127.0.0.1",
        "%s:%d" % (ip_addr, PORT),
        "localhost:%d" % PORT,
        "127.0.0.1:%d" % PORT,
    ]
    fingerprint = ",".join(allowed_hosts)
    if isinstance(state, dict) and state.get("_bench_trusted_hosts_fp") == fingerprint:
        return
    app.add_middleware(_mw.TrustedHostMiddleware, allowed_hosts=allowed_hosts)
    if isinstance(state, dict):
        state["_bench_trusted_hosts_fp"] = fingerprint


def _start_app(app):
    try:
        viperhttp.stop()
    except Exception:
        pass
    app.run(
        port=PORT,
        wifi=False,
        https=HTTPS_ENABLED,
        http2=HTTP2_ENABLED,
        http2_max_streams=HTTP2_MAX_STREAMS,
        min_workers=SERVER_MIN_WORKERS,
        max_workers=SERVER_MAX_WORKERS,
        bridge_min_workers=BRIDGE_MIN_WORKERS,
        bridge_max_workers=BRIDGE_MAX_WORKERS,
        bridge_queue_size=BRIDGE_QUEUE_SIZE,
        bridge_poll_burst=BRIDGE_POLL_BURST,
        bridge_idle_sleep_ms=BRIDGE_IDLE_SLEEP_MS,
        bridge_autoscale=BRIDGE_AUTOSCALE,
        bridge_enqueue_wait_ms=BRIDGE_ENQUEUE_WAIT_MS,
        bridge_worker_yield_every=BRIDGE_WORKER_YIELD_EVERY,
        bridge_scale_up_max_burst=BRIDGE_SCALE_UP_MAX_BURST,
    )


async def _status_loop(label, status_fn):
    while True:
        try:
            connected, ifconfig = status_fn()
            print("net_status", label, connected, ifconfig)
        except Exception as exc:
            print("net_status_error", label, repr(exc))
        await asyncio.sleep(10)


def start_benchmark_app(ip_addr, status_fn, label):
    import viperhttp_app as appmod

    try:
        viperhttp.set_log_level(SERVER_LOG_LEVEL)
        print("vhttp_log_level", viperhttp.get_log_level())
    except Exception as exc:
        print("vhttp_log_level_error", repr(exc))

    _add_trusted_hosts(appmod.app, ip_addr)
    _start_app(appmod.app)
    print("server_running", viperhttp.is_running())

    loop = asyncio.get_event_loop()
    loop.create_task(_status_loop(label, status_fn))
    loop.run_forever()
