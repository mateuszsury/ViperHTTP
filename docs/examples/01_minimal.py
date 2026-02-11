import viperhttp

app = viperhttp.ViperHTTP(
    title="Minimal API",
    version="1.0.0",
    description="Minimal ViperHTTP app with automatic docs/runtime bootstrap",
)


@app.get("/hello")
def hello():
    return {"message": "ok"}


# No manual viperhttp_bridge import needed.
app.run(port=8080, wifi=False)

