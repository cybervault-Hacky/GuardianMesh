"""Security helpers for the localhost Parent Console HTTP service."""

from __future__ import annotations

import hmac
import html
import ipaddress
import secrets
from dataclasses import dataclass
from http.cookies import Morsel, SimpleCookie
from typing import Any

CSRF_HEADER = "X-GuardianMesh-CSRF"
SESSION_COOKIE = "guardianmesh_console_session"
CSRF_COOKIE = "guardianmesh_console_csrf"


def is_loopback_host(host: str | None) -> bool:
    """Return True only for loopback names/addresses usable by a local parent."""
    if not host:
        return False
    host_part = host.split("@")[-1]
    if host_part.startswith("["):
        normalized = host_part[1:].split("]", 1)[0].lower()
    else:
        normalized = host_part.split(":", 1)[0].lower()
    if normalized in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(normalized).is_loopback
    except ValueError:
        return False


def sanitize_redirect(value: str | None) -> str:
    if value in {"home", "devices", "screen", "alerts", "activity", "settings", "about"}:
        return f"/#{value}"
    return "/#home"


@dataclass(frozen=True)
class ConsoleSession:
    token: str
    csrf_token: str

    def cookies(self, secure: bool = False) -> list[Morsel[str]]:
        cookie: SimpleCookie = SimpleCookie()
        cookie[SESSION_COOKIE] = self.token
        cookie[SESSION_COOKIE]["path"] = "/"
        cookie[SESSION_COOKIE]["httponly"] = not secure
        cookie[SESSION_COOKIE]["samesite"] = "Strict"
        if secure:
            cookie[SESSION_COOKIE]["secure"] = True

        cookie[CSRF_COOKIE] = self.csrf_token
        cookie[CSRF_COOKIE]["path"] = "/"
        cookie[CSRF_COOKIE]["samesite"] = "Strict"
        if secure:
            cookie[CSRF_COOKIE]["secure"] = True
        return list(cookie.values())


def create_session() -> ConsoleSession:
    return ConsoleSession(token=secrets.token_urlsafe(32), csrf_token=secrets.token_urlsafe(32))


def constant_time_equal(left: str | None, right: str | None) -> bool:
    if not left or not right:
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def safe_json(value: Any) -> str:
    import json

    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def safe_html(value: Any) -> str:
    return html.escape(str(value), quote=True)
