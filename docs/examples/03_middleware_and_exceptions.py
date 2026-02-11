import viperhttp

app = viperhttp.ViperHTTP(title="Middleware + Exceptions")


class AppError(Exception):
    pass


@app.exception_handler(AppError)
def app_error_handler(request, exc):
    return viperhttp.JSONResponse(status_code=418, body={"detail": str(exc)})


@app.middleware("http")
async def add_server_header(request, call_next):
    resp = await call_next(request)
    headers = resp.get("headers") or []
    if isinstance(headers, dict):
        headers["X-Server"] = "ViperHTTP"
    else:
        headers.append(("X-Server", "ViperHTTP"))
    resp["headers"] = headers
    return resp


@app.get("/ok")
def ok():
    return {"ok": True}


@app.get("/err")
def err():
    raise AppError("custom failure")


app.run(port=8080, wifi=False)

