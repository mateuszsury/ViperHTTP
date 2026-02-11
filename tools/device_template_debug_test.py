import os
import sys

import viperhttp


def ensure_www():
    try:
        os.mkdir("/www")
    except OSError:
        pass


def expect_parse_error(path):
    try:
        viperhttp.render_template(path, {"name": "x"})
        return None
    except Exception as exc:
        return str(exc)


def main():
    ensure_www()
    path = "/www/bad_tpl_debug.html"
    with open(path, "w") as fp:
        fp.write("line1\n{{ name\nline3\n")

    viperhttp.template_debug(False)
    msg = expect_parse_error(path)
    if not msg:
        print("FAIL: expected parse error (debug off)")
        return 1
    print("DEBUG_OFF:", msg)
    if "line " not in msg or "column " not in msg:
        print("FAIL: parse error missing line/column (debug off)")
        return 1
    if "near:" in msg:
        print("FAIL: near preview should be disabled by default")
        return 1

    viperhttp.template_debug(True)
    msg = expect_parse_error(path)
    if not msg:
        print("FAIL: expected parse error (debug on)")
        return 1
    print("DEBUG_ON:", msg)
    if "near:" not in msg:
        print("FAIL: near preview missing in debug mode")
        return 1

    viperhttp.template_debug(False)
    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

