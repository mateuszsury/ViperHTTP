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


def has_entry(stats, path):
    entries = stats.get("entries") or []
    for item in entries:
        if item.get("path") == path:
            return True
    return False


def main():
    mkdir_p("/www")
    mkdir_p("/www/tpl_warmup")
    mkdir_p("/www/tpl_warmup/sub")

    write_text("/www/tpl_warmup/main.html", "<h1>{{ title }}</h1>")
    write_text("/www/tpl_warmup/sub/card.j2", "{% if ok %}ok{% else %}no{% endif %}")
    write_text("/www/tpl_warmup/bad.tpl", "{{ broken")
    write_text("/www/tpl_warmup/ignore.txt", "plain text")

    viperhttp.template_clear_cache()
    base = viperhttp.template_stats()
    must((base.get("entries") or []) == [], "cache should be empty before warmup")

    out1 = viperhttp.template_warmup("/www/tpl_warmup")
    must(out1.get("candidates", 0) >= 3, "expected >=3 template candidates")
    must(out1.get("compiled", 0) >= 2, "expected >=2 compiled templates")
    must(out1.get("errors", 0) >= 1, "expected parser error for bad template")

    stats1 = viperhttp.template_stats()
    must("cache_bytes" in stats1, "cache_bytes missing in template_stats")
    must("cache_budget_bytes" in stats1, "cache_budget_bytes missing in template_stats")
    must(stats1.get("cache_bytes", 0) > 0, "cache_bytes should be > 0 after warmup")
    must(stats1.get("cache_budget_bytes", 0) > 0, "cache_budget_bytes should be > 0")
    must(has_entry(stats1, "/www/tpl_warmup/main.html"), "main template missing in cache")
    must(has_entry(stats1, "/www/tpl_warmup/sub/card.j2"), "card template missing in cache")

    out2 = viperhttp.template_warmup("/www/tpl_warmup")
    must(out2.get("cached", 0) >= 2, "second warmup should hit cache")
    must(out2.get("errors", 0) >= 1, "bad template should still report error")

    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
