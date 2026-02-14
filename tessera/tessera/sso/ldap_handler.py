#!/usr/bin/env python3
"""
LDAP/AD authentication using ldap3.
"""

import os
from typing import Optional
from ldap3 import Server, Connection, ALL, SIMPLE


class LDAPAuthenticator:
    def __init__(self, server_uri: str, base_dn: str):
        self.server_uri = server_uri
        self.base_dn = base_dn

    def authenticate(self, username: str, password: str, search_filter: Optional[str] = None) -> bool:
        if not username or not password:
            return False
        server = Server(self.server_uri, get_info=ALL)
        conn = Connection(server, user=username, password=password, authentication=SIMPLE, auto_bind=True)
        if search_filter:
            conn.search(self.base_dn, search_filter)
            return len(conn.entries) > 0
        return True


def from_env() -> LDAPAuthenticator:
    server_uri = os.getenv("LDAP_SERVER_URI")
    base_dn = os.getenv("LDAP_BASE_DN")
    if not (server_uri and base_dn):
        raise ValueError("LDAP_SERVER_URI and LDAP_BASE_DN are required")
    return LDAPAuthenticator(server_uri, base_dn)
