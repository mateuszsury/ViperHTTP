import os
import sys

import viperhttp


def ensure_www():
    try:
        os.mkdir("/www")
    except OSError:
        pass


def main():
    ensure_www()
    path = "/www/bad_tpl.html"
    with open(path, "w") as fp:
        fp.write("line1\n{{ name\nline3\n")

    try:
        viperhttp.render_template(path, {"name": "x"})
        print("FAIL: expected parse error")
        return 1
    except Exception as exc:
        msg = str(exc)
        print("ERROR:", msg)
        if ("line " not in msg) or ("column " not in msg):
            print("FAIL: missing line/column in parse error")
            return 1

    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
