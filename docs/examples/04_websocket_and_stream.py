import viperhttp

app = viperhttp.ViperHTTP(title="WebSocket + Stream")


@app.websocket("/ws/echo")
async def ws_echo(ws):
    await ws.accept()
    while True:
        msg = await ws.receive()
        if msg.get("type") == "close":
            break
        if msg.get("opcode", 2) == 1:
            await ws.send_text("echo:" + msg.get("text", ""))


@app.get("/stream-chunked")
def stream_chunked():
    def gen():
        for i in range(10):
            yield "chunk-%02d\n" % i

    return viperhttp.StreamingResponse(
        body=gen(),
        content_type="text/plain; charset=utf-8",
        chunked=True,
    )


app.run(port=8080, wifi=False)

