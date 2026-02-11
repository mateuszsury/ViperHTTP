# Template Migration Guide

## From string-concatenation handlers to `TemplateResponse`

Before:

```python
@app.get("/page")
def page(name="World"):
    html = "<h1>Hello " + str(name) + "</h1>"
    return viperhttp.Response(body=html, content_type="text/html; charset=utf-8")
```

After:

```python
@app.get("/page")
def page(name="World"):
    return viperhttp.TemplateResponse(
        "/www/page.html",
        context={"name": name},
    )
```

`/www/page.html`:

```html
<h1>Hello {{ name }}</h1>
```

## Recommended migration steps

1. Move HTML strings to `/www/*.html`.
2. Replace direct string concatenation with `TemplateResponse(path, context=...)`.
3. Keep `strict=True` (default) during migration to catch missing keys early.
4. Add stable `ETag` headers for cacheable template routes.
5. Enable stream mode for larger payloads:
   `TemplateResponse(path, context=ctx, stream=True)`.

## Common mapping patterns

- String interpolation:
  `"...%s..."` -> `{{ value }}`
- Conditional fragments:
  `if ...: html += ...` -> `{% if ... %}...{% endif %}`
- Repeated fragments:
  loops -> `{% for item in items %}...{% endfor %}`
- Shared fragments:
  duplicate HTML blocks -> `{% include "partial.html" %}`

## Validation checklist

1. Run parser/runtime template tests.
2. Confirm escaping behavior (`{{ ... }}`) and explicit raw output (`|safe`).
3. Confirm strict mode failures for missing values.
4. Confirm `stream=True` behavior (chunked, optional gzip, cache headers).

