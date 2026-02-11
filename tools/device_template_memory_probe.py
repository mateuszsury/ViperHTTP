import gc
import os

import viperhttp


def ensure_dir(path):
    try:
        os.mkdir(path)
    except OSError:
        pass


def write_text(path, text):
    with open(path, "w") as fp:
        fp.write(text)


def main():
    ensure_dir("/www")
    ensure_dir("/www/tpl_mem")
    path = "/www/tpl_mem/mem_probe.html"
    write_text(
        path,
        (
            "<h1>{{ title }}</h1>\n"
            "{% for item in items %}<p>{{ item }}</p>{% endfor %}\n"
            "<div>{{ raw|safe }}</div>\n"
        ),
    )

    ctx = {
        "title": "Probe",
        "items": ["a", "b", "<c>", "d", "e", "f"],
        "raw": "<strong>x</strong>",
    }

    viperhttp.template_clear_cache()
    gc.collect()
    mem_before = gc.mem_free()
    min_mem = mem_before

    for _ in range(400):
        out = viperhttp.render_template(path, ctx)
        if "Probe" not in out:
            print("FAIL: render mismatch")
            return 1
        gc.collect()
        cur = gc.mem_free()
        if cur < min_mem:
            min_mem = cur

    gc.collect()
    mem_after = gc.mem_free()
    delta = mem_before - mem_after
    stats = viperhttp.template_stats()

    print("mem_before", mem_before)
    print("mem_after", mem_after)
    print("mem_min", min_mem)
    print("mem_delta", delta)
    print("cache_bytes", stats.get("cache_bytes"))
    print("cache_budget_bytes", stats.get("cache_budget_bytes"))

    # Allow small allocator jitter but fail on clear leak signal.
    if delta > 8192:
        print("FAIL: memory leak suspicion")
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
