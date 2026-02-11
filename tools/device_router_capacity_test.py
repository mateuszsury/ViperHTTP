import viperhttp


def fail(msg):
    print("FAIL:", msg)
    return 1


def main():
    viperhttp.reset()
    app = viperhttp.ViperHTTP()

    target_routes = 1000
    for i in range(target_routes):
        path = "/cap%d" % i
        try:
            app.get(path)(lambda i=i: {"id": i})
        except Exception as exc:
            return fail("route add failed at %d: %r" % (i, exc))

    stats = viperhttp.router_stats()
    print("router_stats", stats)
    if int(stats.get("route_count", 0)) < target_routes:
        return fail("route_count too low")
    if int(stats.get("route_capacity", 0)) < target_routes:
        return fail("route_capacity too low")
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
