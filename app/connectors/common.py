from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit


def validate_public_https_url(endpoint: str) -> bool:
    try:
        parsed = urlsplit(endpoint)
        hostname = parsed.hostname or ""
        if (
            parsed.scheme != "https"
            or not hostname
            or not endpoint.isascii()
            or any(ord(char) < 33 or ord(char) > 126 for char in endpoint)
            or hostname.endswith(".")
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
            or len(endpoint) > 2048
            or (parsed.port is not None and not 1 <= parsed.port <= 65535)
            or hostname.lower() in {"localhost", "metadata.google.internal"}
            or hostname.lower().endswith((".localhost", ".local", ".internal"))
        ):
            return False
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            return True
        return address.is_global
    except ValueError:
        return False
