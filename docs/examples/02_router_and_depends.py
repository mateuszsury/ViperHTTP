import viperhttp

app = viperhttp.ViperHTTP(title="Router + Depends")


def get_user():
    return {"id": 1, "name": "alice"}


api = viperhttp.Router(prefix="/api", tags=["api"], deps={"user": viperhttp.Depends(get_user)})


@api.get("/ping")
def ping(user=None):
    return {"pong": True, "user": user}


@api.get(
    "/search",
    query={
        "q": viperhttp.Query("", str),
        "page": viperhttp.Query(1, int),
    },
)
def search(q="", page=1, user=None):
    return {"q": q, "page": page, "user": user}


app.include_router(api)
app.run(port=8080, wifi=False)

