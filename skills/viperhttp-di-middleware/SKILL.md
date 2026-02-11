---
name: viperhttp-di-middleware
description: Implement Dependency Injection (Depends), routers, middleware stack, exception handling, and lifecycle events for the ViperHTTP FastAPI-like API. Use when changing DI resolution, middleware ordering, BaseHTTPMiddleware, or app/router wiring.
---

# ViperHTTP DI and Middleware

## Overview
Own the FastAPI-like control flow on the MicroPython side: dependency resolution, middleware execution, exception handling, and router inclusion.

## Workflow
1. Read references/di-middleware-spec.md.
2. Define execution order: middleware -> dependencies -> handler -> response.
3. Keep DI resolution async-safe and bounded (max depth).
4. Ensure errors map to HTTPException or custom handlers.
5. Update app/router metadata when signature changes.

## Hard Requirements
- Dependency chains must respect max depth and max count.
- Middleware order is deterministic and documented.
- Exceptions must translate to HTTP responses consistently.
- Lifespan events must not block Core 0.
- BackgroundTasks schedule via uasyncio.

## Definition of Done
- Depends resolution works for sync and async deps.
- app.add_middleware and @app.middleware("http") both function.
- Exception handlers dispatch for registered types.
- Router include works with prefix and tags.

## References
- Read references/di-middleware-spec.md.
- Use plan.md in repo as the source of truth for architecture.
