try:
    import ujson as json
except Exception:
    import json

import viperhttp


class ConnectionManager:
    def __init__(self):
        self._all = []
        self._rooms = {}

    def _room_members(self, room):
        if room is None:
            return self._all
        return self._rooms.get(room, [])

    async def connect(self, websocket, room=None):
        await websocket.accept()
        self._all.append(websocket)
        if room is not None:
            self.join_room(websocket, room)
        return websocket

    def join_room(self, websocket, room):
        if room is None:
            return
        if room is not None:
            members = self._rooms.get(room)
            if members is None:
                members = []
                self._rooms[room] = members
            if websocket not in members:
                members.append(websocket)

    def leave_room(self, websocket, room):
        if room is None:
            return
        members = self._rooms.get(room)
        if members is not None:
            while websocket in members:
                members.remove(websocket)
            if not members:
                self._rooms.pop(room, None)

    def disconnect(self, websocket, room=None):
        while websocket in self._all:
            self._all.remove(websocket)
        if room is not None:
            self.leave_room(websocket, room)
        else:
            for key in list(self._rooms.keys()):
                members = self._rooms.get(key, [])
                while websocket in members:
                    members.remove(websocket)
                if not members:
                    self._rooms.pop(key, None)

    async def broadcast_text(self, text, room=None):
        members = list(self._room_members(room))
        for ws in members:
            try:
                await ws.send_text(text)
            except Exception:
                self.disconnect(ws, room=room)

    async def broadcast_json(self, obj, room=None):
        payload = json.dumps(obj)
        await self.broadcast_text(payload, room=room)

    def stats(self):
        rooms = {}
        for room, members in self._rooms.items():
            rooms[room] = len(members)
        return {"connections": len(self._all), "rooms": rooms}


try:
    setattr(viperhttp, "ConnectionManager", ConnectionManager)
except Exception:
    pass
