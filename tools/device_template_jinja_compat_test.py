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


def main():
    mkdir_p("/www")
    mkdir_p("/www/tpl_compat")

    tpl_path = "/www/tpl_compat/jinja_compat.html"
    write_text(
        tpl_path,
        (
            "{% set local = name|default('anon')|trim %}\n"
            "{% if local == 'Ana' and count >= 2 %}COND_OK{% else %}COND_BAD{% endif %}\n"
            "{% if role in roles %}ROLE_IN{% endif %}\n"
            "{% if 'admin' not in roles %}NO_ADMIN{% endif %}\n"
            "{% if missing is undefined %}UNDEF_OK{% endif %}\n"
            "{% if none_val is none %}NONE_OK{% endif %}\n"
            "{% if local is string %}STR_OK{% endif %}\n"
            "{% for item in items %}"
            "I={{ loop.index }}/{{ loop.length }}/{{ loop.revindex0 }}:{{ item|replace('<', '(')|replace('>', ')') }};"
            "{% else %}NO_ITEMS{% endfor %}\n"
            "JOIN={{ items|join(' | ') }}\n"
            "TITLE={{ local|title }}\n"
            "CAP={{ local|capitalize }}\n"
        ),
    )

    out = viperhttp.render_template(
        tpl_path,
        {
            "name": " Ana ",
            "count": 2,
            "role": "user",
            "roles": ["user", "viewer"],
            "items": ["a", "<b>", "c"],
            "none_val": None,
        },
    )
    must("COND_OK" in out, "and/comparison failed")
    must("ROLE_IN" in out, "in operator failed")
    must("NO_ADMIN" in out, "not in operator failed")
    must("UNDEF_OK" in out, "is undefined failed")
    must("NONE_OK" in out, "is none failed")
    must("STR_OK" in out, "is string failed")
    must("I=1/3/2:a;" in out, "loop metadata index/length/revindex0 failed")
    must("I=2/3/1:(b);" in out, "replace filter failed")
    must("JOIN=a | &lt;b&gt; | c" in out, "join filter failed")
    must("TITLE=Ana" in out, "title filter failed")
    must("CAP=Ana" in out, "capitalize filter failed")

    out_empty = viperhttp.render_template(
        tpl_path,
        {
            "name": "Ana",
            "count": 2,
            "role": "user",
            "roles": ["user"],
            "items": [],
            "none_val": None,
        },
    )
    must("NO_ITEMS" in out_empty, "for-else branch failed")

    print("PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
