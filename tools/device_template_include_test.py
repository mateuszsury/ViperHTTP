import os
import sys

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


def main():
    try:
        viperhttp.template_clear_cache()
    except Exception:
        pass

    mkdir_p("/www")
    mkdir_p("/www/inc")
    mkdir_p("/www/depth")

    write_text("/www/inc/row.html", "<li>{{ item }}</li>")
    write_text("/www/include_main.html", "<ul>{% for item in items %}{% include \"inc/row.html\" %}{% endfor %}</ul>")

    out = viperhttp.render_template("/www/include_main.html", {"items": ["a", "<b>"]})
    must("<li>a</li>" in out, "include basic content missing")
    must("<li>&lt;b&gt;</li>" in out, "include escaping mismatch")

    write_text("/www/include_traversal.html", "{% include \"../../boot.py\" %}")
    try:
        viperhttp.render_template("/www/include_traversal.html", {})
        must(False, "path traversal should fail")
    except Exception:
        pass

    max_depth = 8
    for i in range(max_depth + 2):
        cur = "/www/depth/d%d.html" % i
        if i < max_depth + 1:
            nxt = "d%d.html" % (i + 1)
            write_text(cur, '{% include "' + nxt + '" %}')
        else:
            write_text(cur, "ok")
    try:
        viperhttp.render_template("/www/depth/d0.html", {})
        must(False, "include depth should fail")
    except Exception:
        pass

    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
