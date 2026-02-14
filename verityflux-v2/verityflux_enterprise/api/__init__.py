from importlib import import_module

def __getattr__(name):
    if name == "v2":
        return import_module("verityflux_enterprise.api.v2")
    raise AttributeError(name)
