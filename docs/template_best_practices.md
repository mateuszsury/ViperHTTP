# Template Best Practices

## Structure

1. Keep page templates in `/www` and partials in `/www/partials`.
2. Use includes for repeated sections (`header`, `footer`, cards).
3. Keep templates mostly declarative. Prepare complex values in handler context.

## Performance

1. Precompile after boot:
   `viperhttp.template_warmup("/www")`
2. Keep templates small and composable.
3. Prefer `stream=True` for larger pages to avoid large intermediate buffers.
4. Keep cacheable routes deterministic and attach route-level `ETag`.

## Safety

1. Default output is escaped. Keep it that way.
2. Use `|safe` only for trusted, sanitized HTML fragments.
3. Keep `strict=True` in production unless you explicitly need tolerant mode.
4. Do not encode business logic in templates.

## Debugging

1. Keep debug mode off by default:
   `viperhttp.template_debug(False)`
2. Enable temporarily when diagnosing parse/runtime issues:
   `viperhttp.template_debug(True)`
3. Disable again after diagnosis.

## Load and regression checks

1. Run parser vectors and runtime matrix tests after template changes.
2. Run host HTTP regression (`tools/host_full_test.py`).
3. Re-run device template cache regression for leak checks.

