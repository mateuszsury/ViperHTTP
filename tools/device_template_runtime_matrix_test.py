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


def fail(msg):
    print("FAIL:", msg)
    return 1


def main():
    viperhttp.template_debug(False)
    ensure_dir("/www")
    ensure_dir("/www/tpl_runtime")

    write_text(
        "/www/tpl_runtime/main.html",
        (
            "X={{ x }}\n"
            "RAW={{ raw|safe }}\n"
            "DEF={{ missing|default('d') }}\n"
            "{% set who = x|trim %}\n"
            "{% if who == '<Ab>' and count >= 2 %}COND=OK{% else %}COND=BAD{% endif %}\n"
            "{% if 'a' in items and 'z' not in items %}IN=OK{% endif %}\n"
            "{% if missing2 is undefined and missing is none %}TESTS=OK{% endif %}\n"
            "UP={{ x|upper }}\n"
            "LOW={{ x|lower }}\n"
            "LEN={{ items|length }}\n"
            "PAIRS={% for k, v in pairs.items %}{{ k }}={{ v }};{% endfor %}\n"
            "{% for item in items %}[{{ item }}]{% else %}[EMPTY]{% endfor %}\n"
            "{% raw %}RAWBLOCK={{ no_eval }}{% endraw %}\n"
            "TRIM=A   {{- 'x' -}}   B\n"
            "{% include \"part.html\" %}\n"
        ),
    )
    write_text("/www/tpl_runtime/part.html", "PART={{ x }}")

    out = viperhttp.render_template(
        "/www/tpl_runtime/main.html",
        {"x": "<Ab>", "raw": "<i>ok</i>", "missing": None, "items": ["a", "<b>"], "pairs": {"a": 1, "b": 2}, "count": 2},
    )
    if "X=&lt;Ab&gt;" not in out:
        return fail("escape failed")
    if "RAW=<i>ok</i>" not in out:
        return fail("safe filter failed")
    if "DEF=d" not in out:
        return fail("default filter failed")
    if "COND=OK" not in out:
        return fail("comparison/and failed")
    if "IN=OK" not in out:
        return fail("in/not in failed")
    if "TESTS=OK" not in out:
        return fail("is test failed")
    if "UP=&lt;AB&gt;" not in out:
        return fail("upper filter failed")
    if "LOW=&lt;ab&gt;" not in out:
        return fail("lower filter failed")
    if "LEN=2" not in out:
        return fail("length filter failed")
    if "[a][&lt;b&gt;]" not in out:
        return fail("loop/escape failed")
    if "PAIRS=a=1;b=2;" not in out and "PAIRS=b=2;a=1;" not in out:
        return fail("for-unpack dict.items failed")
    if "RAWBLOCK={{ no_eval }}" not in out:
        return fail("raw block failed")
    if "TRIM=AxB" not in out:
        return fail("whitespace control failed")
    if "PART=&lt;Ab&gt;" not in out:
        return fail("include failed")

    out_empty = viperhttp.render_template(
        "/www/tpl_runtime/main.html",
        {"x": "<Ab>", "raw": "<i>ok</i>", "missing": None, "items": [], "pairs": {"a": 1}, "count": 2},
    )
    if "[EMPTY]" not in out_empty:
        return fail("for-else failed")

    # strict=False should render missing vars as empty
    write_text("/www/tpl_runtime/strict.html", "U={{ missing }}")
    out = viperhttp.render_template("/www/tpl_runtime/strict.html", {}, strict=False)
    if out != "U=":
        return fail("strict=False behavior mismatch")

    # strict=True should raise
    try:
        viperhttp.render_template("/www/tpl_runtime/strict.html", {}, strict=True)
        return fail("strict=True should fail")
    except Exception:
        pass

    # Include-depth limit should trigger.
    depth = 20
    for i in range(depth):
        cur = "/www/tpl_runtime/d%d.html" % i
        nxt = "d%d.html" % (i + 1)
        if i == depth - 1:
            write_text(cur, "END")
        else:
            write_text(cur, '{% include "' + nxt + '" %}')
    try:
        viperhttp.render_template("/www/tpl_runtime/d0.html", {})
        return fail("include depth limit should fail")
    except Exception:
        pass

    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
