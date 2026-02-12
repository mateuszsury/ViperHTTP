# Contributing to ViperHTTP

Thank you for contributing! This guide covers the development workflow, coding standards, and PR expectations.

## Code of Conduct

This project follows the [Contributor Covenant Code of Conduct](CODE_OF_CONDUCT.md). By participating, you agree to uphold these standards.

## Development Scope

- Core C runtime and parser/router/IPC work lives in `cmodules/viperhttp/`.
- MicroPython-facing API and runtime glue live in `viperhttp_*.py`.
- Validation scripts are in `tools/` and `tests/`.
- Documentation lives in `docs/` and is built with MkDocs.

## Local Setup

1. Use Python 3.11+ for host scripts.
2. For firmware build/flash, use the WSL + ESP-IDF flow described in `docs/build.md`.
3. Keep changes focused: runtime/core/docs/testing in the same PR only when tightly coupled.

## Commit Message Convention

This project uses [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <description>

[optional body]

[optional footer]
```

Types:
- `feat` — new feature
- `fix` — bug fix
- `docs` — documentation changes
- `refactor` — code restructuring without behavior change
- `test` — adding or updating tests
- `chore` — build, CI, tooling changes
- `perf` — performance improvements

Examples:
```
feat(router): add wildcard path parameter support
fix(parser): handle malformed Content-Length header
docs: add WebSocket guide to documentation site
chore(ci): add MkDocs build to GitHub Actions workflow
```

## Branch Naming

Use descriptive branch names with a type prefix:

```
feat/websocket-rooms
fix/parser-overflow
docs/security-guide
refactor/bridge-cleanup
```

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

Documentation changes:

```bash
mkdocs build --strict
```

## Coding Guidelines

- Keep performance-critical C code explicit and measurable.
- Preserve API ergonomics in the FastAPI-style surface (`viperhttp` module).
- Avoid breaking public behavior silently; document changes in `CHANGELOG.md`.
- Prefer incremental commits with clear messages.
- Follow existing code patterns and naming conventions.

## Pull Request Checklist

- [ ] Problem and scope are clearly described.
- [ ] Commit messages follow Conventional Commits format.
- [ ] Tests were run (host and/or device) and results are included.
- [ ] Docs were updated (`README` and/or `docs/*`) when behavior changed.
- [ ] Backward-compatibility risks are noted.
- [ ] `CHANGELOG.md` updated for user-facing changes.

## Getting Help

- **Issues**: Open a [GitHub issue](https://github.com/mateuszsury/ViperHTTP/issues) for bugs or feature requests.
- **Discussions**: Use issues for questions about the codebase or architecture.
- **Security**: Report vulnerabilities privately via [SECURITY.md](SECURITY.md).
