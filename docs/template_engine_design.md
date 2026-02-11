# ViperHTTP Template Engine Design (C-side)

## Implementation status (current)
- Implemented (MVP): `TemplateResponse`, `render_template`, cache APIs (`template_clear_cache`, `template_stats`).
- Implemented syntax/runtime: variables, HTML escaping by default, `if/elif/else`, `for`, `for...else`, `set`, `include`, comments, `raw/endraw`, whitespace control.
- Implemented condition operators/tests: `and`, `or`, `not`, `==`, `!=`, `<`, `<=`, `>`, `>=`, `in`, `not in`, `is` tests (`defined`, `undefined`, `none`, `true`, `false`, `string`, `number`, `iterable`).
- Implemented filters: `escape`, `safe`, `default`, `upper`, `lower`, `length`, `join`, `trim`, `replace`, `capitalize`, `title`.
- Implemented safety/perf guards: strict mode toggle, loop/depth/size limits, VFS read lock, template cache lock (recursive mutex), cache invalidate by `(path, size, mtime)`.
- Implemented compile-time diagnostics: deterministic parse errors include `line` and `column`.
- Implemented stability hardening: template cache `source/root` pointers are kept as GC roots in `MP_STATE_VM` to prevent GC collection under load.
- Implemented include safety: include path normalization, root sandboxing, traversal blocking, include-depth guard.
- Implemented soft-reset hardening: cache free path validates GC pointers before releasing cached AST/source buffers.
- Implemented cache budget control: byte-budgeted cache with LRU eviction and PSRAM-aware budget selection.
- Implemented warmup API: `template_warmup(root="/www")` precompiles templates after boot.
- Implemented streaming renderer path: `TemplateResponse(..., stream=True)` renders directly to chunked IPC stream.
- Implemented stream pipeline compatibility: template stream supports `ETag`/`If-None-Match` (`304`) and
  on-the-fly gzip (`Accept-Encoding: gzip`) in C path.
- Implemented template debug mode: `template_debug([enabled])`, default off, with parse-line preview (`near:`).
- Implemented compiler optimization pass: static text coalescing and constant folding for literal `if` conditions.

## 1. Goals
- C-side rendering for dynamic HTML with low overhead on ESP32-S3.
- Jinja2-like subset, but deterministic and safe for embedded runtime.
- No Python `eval`, no dynamic code execution in templates.
- Full compatibility with current response pipeline and MicroPython API style.

## 2. Non-goals (Phase 1)
- Full Jinja2 compatibility.
- Arbitrary function calls from templates.
- User-defined filters/macros executed as Python callbacks in hot path.

## 3. Public API (planned)
- `viperhttp.TemplateResponse(path, context=None, status_code=200, headers=None, content_type="text/html; charset=utf-8")`
- `viperhttp.render_template(path, context=None)` for testing and small content.
- `viperhttp.template_clear_cache(path=None)`
- `viperhttp.template_stats()`
- `viperhttp.template_warmup(root="/www")`

## 4. Syntax subset (Phase 1)
- Variable output: `{{ expr }}`
- Statements: `{% if %}`, `{% elif %}`, `{% else %}`, `{% endif %}`
- Loops: `{% for item in items %} ... {% else %} ... {% endfor %}`
- Loop unpacking: `{% for key, value in pairs %} ... {% endfor %}` (2-item tuples/lists)
- Assignment: `{% set name = expr %}`
- Include: `{% include "partial.html" %}`
- Comments: `{# ... #}`
- Raw blocks: `{% raw %} ... {% endraw %}`
- Filters:
- `escape`, `safe`, `default`, `upper`, `lower`, `length`, `join`, `trim`, `replace`, `capitalize`, `title`
- Filter arguments: both `|default:"x"` and `|default("x")` are accepted.
- Dict convenience selectors: `dict.items`, `dict.keys`, `dict.values`
- Whitespace control markers: `{{- ... -}}`, `{%- ... -%}`, `{#- ... -#}`

Escaping rules:
- `{{ ... }}` is escaped by default.
- Raw HTML only through explicit `safe` filter.

## 5. Compiler and runtime architecture

### 5.1 Parse pipeline
1. Load template bytes from VFS.
2. Lexer: zero-copy tokenization over buffer.
3. Parser: produce compact IR (template bytecode).
4. Validate control-flow blocks (`if/endif`, `for/endfor`).
5. Emit bytecode + constant table + symbol table.

### 5.2 Runtime model
- Stack-based bytecode interpreter.
- Read-only context lookup (dict/list/tuple/basic attrs).
- No writes, no side effects.
- Streaming writer interface:
- Direct chunk writes to existing response stream path.
- Avoid full rendered buffer for large templates.

### 5.3 Context lookup
- Dot path lookup: `user.name`, `order.total`.
- Support dict keys first, then read-only attribute access.
- Limits:
- Max expression depth.
- Max include depth.
- Max loop iterations.

## 6. Caching strategy
- Cache key: `(path, file_size, file_mtime, options_hash)`.
- Value: compiled bytecode blob + metadata.
- LRU eviction.
- Configurable RAM budget with PSRAM-aware expansion.
- Stats:
- hit/miss
- compile count
- evictions
- bytes used

## 7. Security model
- No function invocation from templates in Phase 1.
- No mutation operations.
- Include path sandboxed to configured root.
- Path traversal blocked (`..`, absolute path escape).
- Optional strict undefined mode:
- undefined variable => render error
- relaxed mode => empty string

## 8. Integration points
- New response constructor in C module (similar to existing `FileResponse` and `StreamingResponse` flow).
- Reuse existing headers/content-type serialization path.
- Compatible with middleware chain and route dispatch.
- Logging:
- compile start/finish (debug level)
- cache hit/miss (trace/debug)
- render errors (error)

## 9. Performance targets
- Warm cache p95 overhead <= 20% vs equivalent pre-generated static HTML.
- Cold compile amortized by cache; subsequent renders near warm path target.
- No OOM during 30 min sustained concurrent load.
- Stable heap profile with no leak across repeated compile/evict cycles.

## 10. Test strategy

### 10.1 Host tests
- Lexer/parser vectors:
- valid syntax
- invalid syntax with line/column checks
- Runtime vectors:
- escaping correctness
- if/for/include behavior
- filter semantics
- limit enforcement

### 10.2 Device E2E
- Route-level `TemplateResponse` on ESP32-S3.
- Concurrent request load.
- Cache invalidation after template file update.
- Include depth and loop limit guard checks.
- Dedicated regression script: `tools/device_template_cache_regression_test.py`
- validates invalidation, LRU eviction, budget guard, and memory leak regression (`gc.mem_free` delta check).

### 10.3 Benchmarks
- Compare:
- static file
- plain `Response`
- `TemplateResponse` cold
- `TemplateResponse` warm
- Collect:
- req/s
- p50/p95/p99 latency
- RAM/PSRAM deltas

## 11. Rollout plan
- Milestone A (MVP):
- variables + escaping + `if` + `for` + `TemplateResponse`.
- Milestone B:
- include + filters + cache APIs + stats.
- Milestone C:
- PSRAM tuning + benchmark gates + docs/examples.

## 12. Risks and mitigations
- Risk: parser complexity grows too fast.
- Mitigation: freeze minimal grammar first, reject unsupported constructs explicitly.
- Risk: runtime fragmentation from many compiled templates.
- Mitigation: contiguous bytecode blobs + LRU + hard memory budgets.
- Risk: security regressions in lookup/include.
- Mitigation: strict resolver policy and dedicated fuzz/vector tests.

## 13. Related docs
- Migration guide: `docs/template_migration.md`
- Best practices: `docs/template_best_practices.md`
