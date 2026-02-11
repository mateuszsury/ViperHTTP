# MicroPython API Spec Extract (ViperHTTP)

## App Basics
- from viperhttp import ViperHTTP, Router, Depends
- app = ViperHTTP(title="App", version="1.0.0")
- app.run(host="0.0.0.0", port=80)

## Routing (FastAPI-like)
- @app.get("/path")
- @app.post("/path")
- @app.websocket("/ws")
- Path params: "/items/{item_id:int}"
- Query params via function args with defaults
- Return dict or list => auto JSON response

## Dependencies
- def get_db(): return ...
- @app.get("/items")
  async def list_items(db=Depends(get_db)):
      return ...
- BackgroundTasks: injected when requested

## Routers
- router = Router(prefix="/api", tags=["api"])
- app.include_router(router)

## Middleware
- app.add_middleware(CORSMiddleware, allow_origins=["*"])
- app.add_middleware(GZipMiddleware, minimum_size=500)
- @app.middleware("http") async def mw(request, call_next): ...
- BaseHTTPMiddleware for custom Python middleware

## Requests and Responses
- Request: headers, path, query_params, state
- Response classes: StreamingResponse, FileResponse, RedirectResponse
- SSE: EventSourceResponse
- UploadFile for multipart uploads
- HTTPException for error responses
- app.exception_handler(ExceptionType)

## Lifespan Events
- @app.on_event("startup")
- @app.on_event("shutdown")

## WebSocket
- async def ws(ws: WebSocket):
  await ws.accept(); await ws.send_json(...)
- ConnectionManager for broadcast helpers
