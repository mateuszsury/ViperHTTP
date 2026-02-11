import viperhttp

_APP_RUNTIME = {}


def _app_key(app):
    try:
        return id(app)
    except Exception:
        return None


def _runtime(app):
    key = _app_key(app)
    if key is None:
        return {"state": {}, "events": {"startup": [], "shutdown": []}, "exception_handlers": {}}
    rt = _APP_RUNTIME.get(key)
    if rt is None:
        rt = {
            "state": {},
            "events": {"startup": [], "shutdown": []},
            "exception_handlers": {},
        }
        _APP_RUNTIME[key] = rt
    return rt


def get_app_state(app):
    return _runtime(app)["state"]


def get_event_handlers(app, event):
    event_name = str(event).lower()
    if event_name not in ("startup", "shutdown"):
        return []
    return _runtime(app)["events"][event_name]


def add_event_handler(app, event, handler):
    event_name = str(event).lower()
    if event_name not in ("startup", "shutdown"):
        raise ValueError("event must be 'startup' or 'shutdown'")
    if not callable(handler):
        raise TypeError("event handler must be callable")
    handlers = _runtime(app)["events"][event_name]
    handlers.append(handler)
    return handler


def on_event(app, event):
    def decorator(func):
        add_event_handler(app, event, func)
        return func
    return decorator


def add_exception_handler(app, exc_type, handler):
    if exc_type is None:
        raise TypeError("exc_type is required")
    if not callable(handler):
        raise TypeError("handler must be callable")
    _runtime(app)["exception_handlers"][exc_type] = handler
    return handler


def exception_handler(app, exc_type):
    def decorator(func):
        add_exception_handler(app, exc_type, func)
        return func
    return decorator


def resolve_exception_handler(app, exc):
    handlers = _runtime(app)["exception_handlers"]
    if not handlers or exc is None:
        return None

    exc_type = type(exc)
    mro = None
    try:
        mro = exc_type.mro()
    except Exception:
        mro = None

    if mro:
        for cls in mro:
            if cls in handlers:
                return handlers[cls]

    for cls, handler in handlers.items():
        try:
            if isinstance(exc, cls):
                return handler
        except Exception:
            continue
    return None


def _on_event(self, event):
    def decorator(func):
        add_event_handler(self, event, func)
        return func
    return decorator


def _exception_handler(self, exc_type):
    def decorator(func):
        add_exception_handler(self, exc_type, func)
        return func
    return decorator


def _state_getter(self):
    return get_app_state(self)


def install():
    try:
        setattr(viperhttp.ViperHTTP, "on_event", _on_event)
    except Exception:
        pass
    try:
        setattr(viperhttp.ViperHTTP, "exception_handler", _exception_handler)
    except Exception:
        pass
    try:
        setattr(viperhttp.ViperHTTP, "state", property(_state_getter))
    except Exception:
        pass


install()
