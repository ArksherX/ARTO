from importlib import import_module

def __getattr__(name):
    if name == "python":
        return import_module("verityflux_enterprise.sdk.python")
    raise AttributeError(name)
