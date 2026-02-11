# DI + Middleware Spec Extract (ViperHTTP)

## DI (Depends)
- Depends() resolves a chain of callables.
- Support sync and async dependencies.
- Enforce max dependencies per route: 16
- Enforce max chain depth: 8
- Inject BackgroundTasks when requested.

## Router
- Router(prefix=..., tags=[...])
- app.include_router(router)
- Route metadata stores dependencies and expected_status

## Middleware
- app.add_middleware(CORSMiddleware, ...)
- app.add_middleware(GZipMiddleware, ...)
- @app.middleware("http") for custom Python middleware
- BaseHTTPMiddleware for class-based middleware
- Execution order: C-native middleware (Core 0) -> Python middleware -> deps -> handler

## Exceptions
- HTTPException(status_code, detail)
- app.exception_handler(ExceptionType)
- Unhandled exceptions map to 500

## Lifespan
- @app.on_event("startup")
- @app.on_event("shutdown")
- Must run on Core 1 without blocking Core 0
