import viperhttp

app = viperhttp.ViperHTTP(
    title="HTTPS + HTTP/2",
    version="1.0.0",
    description="TLS and HTTP/2 enabled app",
)


@app.get("/hello")
def hello():
    return {"message": "secure"}


app.run(
    port=8080,
    wifi=False,
    https=True,
    http2=True,
    http2_max_streams=8,
    tls_cert_path="/certs/server.crt",
    tls_key_path="/certs/server.key",
)

