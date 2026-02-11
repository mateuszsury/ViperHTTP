# Contributing to ViperHTTP

Thank you for contributing.

## Development Scope

- Core C runtime and parser/router/IPC work lives in `cmodules/viperhttp/`.
- MicroPython-facing API and runtime glue live in `viperhttp_*.py`.
- Validation scripts are in `tools/` and `tests/`.

## Local Setup

1. Use Python 3.11+ for host scripts.
2. For firmware build/flash, use the WSL + ESP-IDF flow described in `docs/build.md`.
3. Keep changes focused: runtime/core/docs/testing in the same PR only when tightly coupled.

## Validation Before PR

Run host tests:

```bash
./tools/run_parser_tests.sh
./tools/run_router_tests.sh
./tools/run_pool_tests.sh
./tools/run_pipeline_tests.sh
./tools/run_ipc_tests.sh
```

If you touched runtime behavior, run relevant device tests from `tools/` and include results in the PR description.

## Coding Guidelines

- Keep performance-critical C code explicit and measurable.
- Preserve API ergonomics in the FastAPI-style surface (`viperhttp` module).
- Avoid breaking public behavior silently; document changes in `CHANGELOG.md`.
- Prefer incremental commits with clear messages.

## Pull Request Checklist

- [ ] Problem and scope are clearly described.
- [ ] Tests were run (host and/or device) and results are included.
- [ ] Docs were updated (`README` and/or `docs/*`) when behavior changed.
- [ ] Backward-compatibility risks are noted.
