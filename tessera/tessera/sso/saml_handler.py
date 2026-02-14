#!/usr/bin/env python3
"""
SAML 2.0 validation using python3-saml.
"""

import os
from typing import Dict

try:
    from onelogin.saml2.auth import OneLogin_Saml2_Auth
except Exception:  # pragma: no cover - optional dependency
    OneLogin_Saml2_Auth = None


class SAMLValidator:
    def __init__(self, settings: Dict):
        self.settings = settings

    def validate_response(self, request_data: Dict) -> Dict:
        if OneLogin_Saml2_Auth is None:
            raise ImportError("SAML support requires python3-saml (onelogin). Install it to use SAML.")
        auth = OneLogin_Saml2_Auth(request_data, self.settings)
        auth.process_response()
        errors = auth.get_errors()
        if errors:
            raise ValueError(f"SAML validation errors: {errors}")
        if not auth.is_authenticated():
            raise ValueError("SAML authentication failed")
        return {
            "name_id": auth.get_nameid(),
            "attributes": auth.get_attributes()
        }


def from_env() -> SAMLValidator:
    settings_path = os.getenv("SAML_SETTINGS_PATH")
    if not settings_path:
        raise ValueError("SAML_SETTINGS_PATH is required")
    with open(settings_path, "r", encoding="utf-8") as f:
        import json
        settings = json.load(f)
    return SAMLValidator(settings)

__all__ = ["SAMLValidator", "from_env"]
