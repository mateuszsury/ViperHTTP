# Device smoke test for ViperHTTP
import network
import viperhttp
import viperhttp_app as appmod
import viperhttp_bridge as bridge

print("version", viperhttp.version())
print("current_request_none", viperhttp.current_request() is None)

appmod.app.run()
print("app_run", True)
print("server_running", viperhttp.is_running())

resp = appmod.app.dispatch("GET", "/hello")
print("hello", resp.get("status_code"), resp.get("body"))
resp = appmod.app.dispatch("GET", "/items/42")
print("item", resp.get("status_code"), resp.get("body"))

resp = appmod.app.dispatch("GET", "/query?q=foo&page=2")
print("query", resp.get("status_code"), resp.get("body"))

resp = appmod.app.dispatch("GET", "/query-typed?q=hi&page=3&ratio=1.5&active=true")
print("query_typed", resp.get("status_code"), resp.get("body"))
resp = appmod.app.dispatch("GET", "/query-typed?q=hi")
print("query_missing", resp.get("status_code"), resp.get("body"))
resp = appmod.app.dispatch("GET", "/query-typed?q=hi&page=bad&ratio=1.2")
print("query_invalid", resp.get("status_code"), resp.get("body"))

resp = appmod.app.dispatch("GET", "/deps")
print("deps", resp.get("status_code"), resp.get("body"))
resp = appmod.app.dispatch("GET", "/api/ping")
print("router_ping", resp.get("status_code"), resp.get("body"))

resp = viperhttp.Response(body="ok")
ser = bridge.serialize_response(resp)
print("serialized", ser.get("__vhttp_response__"), ser.get("body"))
viperhttp.send_response(1, resp)
print("send_ok")
print("ipc_stats", viperhttp.ipc_stats())
