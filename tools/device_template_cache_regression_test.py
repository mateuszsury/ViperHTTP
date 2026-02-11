import gc
import os

import viperhttp


def mkdir_p(path):
    try:
        os.mkdir(path)
    except OSError:
        pass


def write_text(path, text):
    with open(path, "w") as fp:
        fp.write(text)


def must(cond, msg):
    if not cond:
        print("FAIL:", msg)
        raise SystemExit(1)


def stat_entry(stats, path):
    entries = stats.get("entries") or []
    for item in entries:
        if item.get("path") == path:
            return item
    return None


def main():
    mkdir_p("/www")
    mkdir_p("/www/tpl_reg")

    path = "/www/tpl_reg/page.html"

    # Invalidation by (size, mtime): changed file must trigger recompile.
    viperhttp.template_clear_cache()
    write_text(path, "v1 {{ name }}")
    out = viperhttp.render_template(path, {"name": "Ana"})
    must(out == "v1 Ana", "first render mismatch")
    s1 = viperhttp.template_stats()
    c1 = int(s1.get("compiles", 0))
    e1 = stat_entry(s1, path)
    must(e1 is not None, "cache entry missing after first render")

    # Change size so invalidation does not depend only on mtime resolution.
    write_text(path, "v2 updated {{ name }}")
    out2 = viperhttp.render_template(path, {"name": "Ana"})
    must(out2 == "v2 updated Ana", "cache invalidation did not pick new content")
    s2 = viperhttp.template_stats()
    c2 = int(s2.get("compiles", 0))
    must(c2 >= c1 + 1, "compile counter did not increase after template update")

    # Eviction behavior: exceed capacity with unique templates.
    viperhttp.template_clear_cache()
    cap = int(viperhttp.template_stats().get("capacity", 0))
    must(cap > 0, "invalid cache capacity")
    total = cap + 4
    for i in range(total):
        p = "/www/tpl_reg/e%02d.html" % i
        write_text(p, "evict-%d {{ name }}" % i)
        rendered = viperhttp.render_template(p, {"name": "x"})
        must(rendered == "evict-%d x" % i, "eviction render mismatch at %d" % i)
    se = viperhttp.template_stats()
    entries = se.get("entries") or []
    must(len(entries) <= cap, "entries exceed cache capacity")
    must(int(se.get("cache_evicts", 0)) >= 1, "expected at least one cache eviction")
    must(int(se.get("cache_bytes", 0)) <= int(se.get("cache_budget_bytes", 0)), "cache bytes exceed budget")

    # Leak regression: repeatedly invalidate same path with varying template sizes.
    viperhttp.template_clear_cache()
    gc.collect()
    base_free = gc.mem_free()

    for i in range(120):
        payload = ("x" * (8 + (i % 48)))
        write_text(path, "<p>%s {{ name }}</p>" % payload)
        rendered = viperhttp.render_template(path, {"name": "zz"})
        must("zz" in rendered, "loop render failed at %d" % i)

    viperhttp.template_clear_cache()
    gc.collect()
    end_free = gc.mem_free()
    leak = base_free - end_free
    # Conservative threshold for allocator noise on-device.
    must(leak < 16 * 1024, "possible memory leak, mem_free delta=%d" % leak)

    print("PASS")
    print("capacity", cap)
    print("leak_delta", leak)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
