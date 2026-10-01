"""Test-suite configuration for VerityFlux.

Enables permissive development authentication for the whole suite. The unit
tests authenticate with arbitrary bearer tokens (dev convenience); production
defaults to secure (VERITYFLUX_DEV_AUTH unset -> unverifiable credentials are
rejected). setdefault means a developer can still force VERITYFLUX_DEV_AUTH=false
to exercise the secure path without this file overriding them.
"""
import os

os.environ.setdefault("VERITYFLUX_DEV_AUTH", "true")
