import os
import sys

import viperhttp


def ensure_dir(path):
    try:
        os.mkdir(path)
    except OSError:
        pass


def write_text(path, text):
    with open(path, "w") as fp:
        fp.write(text)


def expect_ok(path, ctx, needle):
    try:
        out = viperhttp.render_template(path, ctx)
    except Exception as exc:
        print("FAIL: expected success:", path, repr(exc))
        return False
    if needle not in out:
        print("FAIL: expected fragment missing:", path, repr(needle))
        print("OUT:", out)
        return False
    return True


def expect_parse_error(path):
    try:
        viperhttp.render_template(path, {"name": "x"})
    except Exception as exc:
        msg = str(exc)
        if ("line " not in msg) or ("column " not in msg):
            print("FAIL: parse error without line/column:", path, msg)
            return False
        return True
    print("FAIL: expected parse error:", path)
    return False


def main():
    viperhttp.template_debug(False)
    ensure_dir("/www")
    ensure_dir("/www/tpl_vectors")

    write_text("/www/tpl_vectors/inc_part.html", "INC={{ part }}")

    # Valid vectors.
    write_text("/www/tpl_vectors/v1.html", "Hello {{ name }}")
    write_text("/www/tpl_vectors/v2.html", "{% if show %}ON{% else %}OFF{% endif %}")
    write_text("/www/tpl_vectors/v3.html", "{% for item in items %}[{{ item }}]{% endfor %}")
    write_text("/www/tpl_vectors/v4.html", "{% include \"inc_part.html\" %}")
    write_text(
        "/www/tpl_vectors/v5.html",
        "{% if true %}A{% elif false %}B{% else %}C{% endif %}",
    )
    write_text("/www/tpl_vectors/v6.html", "{% set x = 'ok' %}{{ x }}")
    write_text("/www/tpl_vectors/v7.html", "{% for item in items %}{{ item }}{% else %}E{% endfor %}")
    write_text("/www/tpl_vectors/v8.html", "{% raw %}{{ not_eval }}{% endraw %}")
    write_text("/www/tpl_vectors/v9.html", "A   {{- 'x' -}}   B")
    write_text("/www/tpl_vectors/v10.html", "{% for k, v in data.items %}[{{ k }}={{ v }}]{% endfor %}")

    ok = True
    ok &= expect_ok("/www/tpl_vectors/v1.html", {"name": "Ana"}, "Hello Ana")
    ok &= expect_ok("/www/tpl_vectors/v2.html", {"show": True}, "ON")
    ok &= expect_ok("/www/tpl_vectors/v2.html", {"show": False}, "OFF")
    ok &= expect_ok("/www/tpl_vectors/v3.html", {"items": ["a", "b"]}, "[a][b]")
    ok &= expect_ok("/www/tpl_vectors/v4.html", {"part": "ok"}, "INC=ok")
    ok &= expect_ok("/www/tpl_vectors/v5.html", {}, "A")
    ok &= expect_ok("/www/tpl_vectors/v6.html", {}, "ok")
    ok &= expect_ok("/www/tpl_vectors/v7.html", {"items": []}, "E")
    ok &= expect_ok("/www/tpl_vectors/v8.html", {}, "{{ not_eval }}")
    ok &= expect_ok("/www/tpl_vectors/v9.html", {}, "AxB")
    ok &= expect_ok("/www/tpl_vectors/v10.html", {"data": {"a": 1, "b": 2}}, "[a=1]")

    # Invalid vectors.
    write_text("/www/tpl_vectors/e1.html", "{{ name")
    write_text("/www/tpl_vectors/e2.html", "{% if true %}x")
    write_text("/www/tpl_vectors/e3.html", "{% for x in xs %}x")
    write_text("/www/tpl_vectors/e4.html", "{% unknown x %}")
    write_text("/www/tpl_vectors/e5.html", "{% set x %}")
    write_text("/www/tpl_vectors/e6.html", "{% raw %}x")

    ok &= expect_parse_error("/www/tpl_vectors/e1.html")
    ok &= expect_parse_error("/www/tpl_vectors/e2.html")
    ok &= expect_parse_error("/www/tpl_vectors/e3.html")
    ok &= expect_parse_error("/www/tpl_vectors/e4.html")
    ok &= expect_parse_error("/www/tpl_vectors/e5.html")
    ok &= expect_parse_error("/www/tpl_vectors/e6.html")

    if not ok:
        return 1
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
