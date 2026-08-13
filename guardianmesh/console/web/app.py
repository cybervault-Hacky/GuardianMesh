"""Local HTTP server serving the Parent Console UI."""

from __future__ import annotations

import json
import mimetypes
import threading
import webbrowser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, unquote, urlparse

from guardianmesh import __phase__, __version__
from guardianmesh.console.web.presenter import ParentConsolePresenter
from guardianmesh.console.web.security import (
    CSRF_HEADER,
    SESSION_COOKIE,
    ConsoleSession,
    constant_time_equal,
    create_session,
    is_loopback_host,
    safe_json,
)
from guardianmesh.console.web.settings import ConsoleUISettingsStore
from guardianmesh.core.config import GuardianConfig, load_config
from guardianmesh.core.errors import GuardianMeshError
from guardianmesh.storage.database import Database

STATIC_DIR = Path(__file__).with_name("static")
SAFE_ACTIONS = {
    "screen.request",
    "screen.stop",
    "alerts.acknowledge",
    "alerts.resolve",
    "alerts.dismiss",
    "devices.rename",
    "devices.revoke",
    "pairing.start",
    "settings.update",
}


class ParentConsoleApp:
    """Owns the local service, request handler factory, and session state."""

    def __init__(
        self,
        config: GuardianConfig,
        host: str = "127.0.0.1",
        port: int = 8765,
        open_browser: bool = True,
    ) -> None:
        if host not in {"127.0.0.1", "localhost", "::1"}:
            raise GuardianMeshError("Parent Console can only bind to localhost by default.")
        self.config = config
        self.host = host
        self.port = port
        self.open_browser = open_browser
        self.db = Database(config.database_path)
        self.settings_store = ConsoleUISettingsStore(config)
        self.presenter = ParentConsolePresenter(self.db, config)
        self._sessions: dict[str, ConsoleSession] = {}
        self._lock = threading.RLock()
        self._server: ThreadingHTTPServer | None = None

    def create_session(self) -> ConsoleSession:
        session = create_session()
        with self._lock:
            self._sessions[session.token] = session
        return session

    def valid_session(self, token: str | None, csrf: str | None = None, require_csrf: bool = False) -> bool:
        if not token:
            return False
        with self._lock:
            session = self._sessions.get(token)
        if not session or not constant_time_equal(session.token, token):
            return False
        if require_csrf and not constant_time_equal(session.csrf_token, csrf):
            return False
        return True

    def make_handler(self) -> type[BaseHTTPRequestHandler]:
        app = self

        class ConsoleRequestHandler(BaseHTTPRequestHandler):
            server_version = "GuardianMeshConsole/1.0"

            def log_message(self, format: str, *args: Any) -> None:
                return

            def do_GET(self) -> None:
                if not is_loopback_host(self.headers.get("Host")):
                    self.send_error(HTTPStatus.FORBIDDEN, "Localhost only")
                    return
                parsed = urlparse(self.path)
                if parsed.path.startswith("/api/"):
                    self.handle_api_read(parsed)
                    return
                self.serve_static(parsed.path)

            def do_POST(self) -> None:
                if not is_loopback_host(self.headers.get("Host")):
                    self.send_error(HTTPStatus.FORBIDDEN, "Localhost only")
                    return
                token = self.cookies().get(SESSION_COOKIE)
                csrf = self.headers.get(CSRF_HEADER)
                if not app.valid_session(token, csrf, require_csrf=True):
                    self.send_json(HTTPStatus.FORBIDDEN, {"error": "Session required."})
                    return
                parsed = urlparse(self.path)
                self.handle_api_write(parsed)

            def cookies(self) -> dict[str, str]:
                raw = self.headers.get("Cookie", "")
                result: dict[str, str] = {}
                for part in raw.split(";"):
                    if "=" in part:
                        key, value = part.strip().split("=", 1)
                        result[key] = value
                return result

            def read_json(self) -> dict[str, Any]:
                length = int(self.headers.get("Content-Length", "0") or "0")
                if length <= 0:
                    return {}
                if length > 1_000_000:
                    raise GuardianMeshError("Request is too large.")
                raw = self.rfile.read(length)
                try:
                    data = json.loads(raw.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise GuardianMeshError("Invalid request.") from exc
                if not isinstance(data, dict):
                    raise GuardianMeshError("Invalid request.")
                return data

            def serve_static(self, request_path: str) -> None:
                relative = "index.html" if request_path in {"", "/"} else unquote(request_path.lstrip("/"))
                if not relative or ".." in Path(relative).parts:
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                if relative.startswith("locales/"):
                    candidate = (Path(__file__).parent / relative).resolve()
                    allowed_root = Path(__file__).with_name("locales").resolve()
                else:
                    candidate = (STATIC_DIR / relative).resolve()
                    allowed_root = STATIC_DIR.resolve()
                try:
                    candidate.relative_to(allowed_root)
                except (NameError, ValueError, OSError):
                    self.send_error(HTTPStatus.NOT_FOUND)
                    return
                if not candidate.is_file():
                    candidate = STATIC_DIR / "index.html"
                    allowed_root = STATIC_DIR.resolve()
                content_type = mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
                body = candidate.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header(
                    "Content-Security-Policy",
                    "default-src 'self'; style-src 'self'; script-src 'self'; "
                    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'",
                )
                self.end_headers()
                self.wfile.write(body)

            def handle_api_read(self, parsed: Any) -> None:
                token = self.cookies().get(SESSION_COOKIE)
                if parsed.path == "/api/session":
                    if app.valid_session(token):
                        self.send_json(
                            HTTPStatus.OK, {"authenticated": True, "phase": __phase__, "version": __version__}
                        )
                    else:
                        session = app.create_session()
                        self.send_json(
                            HTTPStatus.OK,
                            {"authenticated": True, "phase": __phase__, "version": __version__},
                            session=session,
                        )
                    return
                if not app.valid_session(token):
                    self.send_json(HTTPStatus.UNAUTHORIZED, {"error": "Session required."})
                    return
                query = parse_qs(parsed.query)
                try:
                    if parsed.path == "/api/bootstrap":
                        settings = app.settings_store.load()
                        body = app.presenter.bootstrap(settings)
                        body["settings"] = app.presenter._settings_dict(settings)
                    elif parsed.path == "/api/home":
                        body = app.presenter.home()
                    elif parsed.path == "/api/devices":
                        body = app.presenter.devices()
                    elif parsed.path == "/api/device":
                        body = app.presenter.device_detail(self.query_value(query, "id"))
                    elif parsed.path == "/api/screen":
                        body = app.presenter.screen_overview(self.query_value(query, "device"))
                    elif parsed.path == "/api/alerts":
                        body = app.presenter.alerts()
                    elif parsed.path == "/api/activity":
                        body = app.presenter.activity(limit=int(self.query_value(query, "limit") or "50"))
                    elif parsed.path == "/api/settings":
                        body = {
                            "ui": app.presenter._settings_dict(app.settings_store.load()),
                            "system": app.presenter.settings_data(),
                        }
                    elif parsed.path == "/api/pairing":
                        body = app.presenter.pairing_overview()
                    elif parsed.path == "/api/diagnostics":
                        body = app.presenter.diagnostics()
                    elif parsed.path == "/api/action":
                        self.send_json(HTTPStatus.METHOD_NOT_ALLOWED, {"error": "Use POST for actions."})
                        return
                    elif parsed.path == "/api/about":
                        body = {
                            "name": "GuardianMesh",
                            "phase": __phase__,
                            "version": __version__,
                            "tagline": "Consent-based parental device supervision.",
                            "license": "MIT",
                            "documentation": "/docs/CONSOLE.md",
                        }
                    else:
                        self.send_json(HTTPStatus.NOT_FOUND, {"error": "Not found."})
                        return
                except GuardianMeshError as exc:
                    self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                except Exception:
                    self.send_json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {"error": "GuardianMesh couldn't complete that request."},
                    )
                    return
                self.send_json(HTTPStatus.OK, body)

            def handle_api_write(self, parsed: Any) -> None:
                try:
                    data = self.read_json()
                    action = data.get("action")
                    if action not in SAFE_ACTIONS:
                        self.send_json(HTTPStatus.FORBIDDEN, {"error": "That action is not allowed."})
                        return
                    if action == "screen.request":
                        body = app.presenter.start_screen_request(
                            str(data["device_id"]), data.get("duration_seconds")
                        )
                    elif action == "screen.stop":
                        body = app.presenter.stop_screen_session(str(data["session_id"]))
                    elif action == "alerts.acknowledge":
                        body = app.presenter.acknowledge_alert(str(data["alert_id"]))
                    elif action == "alerts.resolve":
                        body = app.presenter.resolve_alert(str(data["alert_id"]))
                    elif action == "alerts.dismiss":
                        body = app.presenter.dismiss_alert(str(data["alert_id"]))
                    elif action == "devices.rename":
                        body = app.presenter.rename_device(str(data["device_id"]), str(data["label"]))
                    elif action == "devices.revoke":
                        body = app.presenter.revoke_device(str(data["device_id"]))
                    elif action == "pairing.start":
                        body = app.presenter.start_pairing(
                            str(data.get("method", "DEMO")),
                            str(data.get("destination", "demo@guardianmesh.local")),
                        )
                    elif action == "settings.update":
                        settings = app.settings_store.update(data.get("settings", {}))
                        body = {"settings": app.presenter._settings_dict(settings)}
                    else:  # pragma: no cover - guarded by SAFE_ACTIONS
                        self.send_json(HTTPStatus.FORBIDDEN, {"error": "That action is not allowed."})
                        return
                except KeyError as exc:
                    self.send_json(HTTPStatus.BAD_REQUEST, {"error": f"Missing field: {exc.args[0]}"})
                    return
                except GuardianMeshError as exc:
                    self.send_json(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                    return
                except Exception:
                    self.send_json(
                        HTTPStatus.INTERNAL_SERVER_ERROR,
                        {"error": "GuardianMesh couldn't complete that action."},
                    )
                    return
                self.send_json(HTTPStatus.OK, body)

            @staticmethod
            def query_value(query: dict[str, list[str]], key: str) -> str:
                values = query.get(key) or []
                return values[0] if values else ""

            def send_json(
                self, status: HTTPStatus, body: dict[str, Any], session: ConsoleSession | None = None
            ) -> None:
                payload = safe_json(body).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(payload)))
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Cache-Control", "no-store")
                if session:
                    for cookie in session.cookies(secure=self.is_secure()):
                        self.send_header("Set-Cookie", cookie.OutputString())
                self.end_headers()
                self.wfile.write(payload)

            def is_secure(self) -> bool:
                return self.headers.get("X-Forwarded-Proto", "http") == "https"

        return ConsoleRequestHandler

    def serve_forever(self) -> None:
        server = ThreadingHTTPServer((self.host, self.port), self.make_handler())
        self.port = server.server_port
        self._server = server
        try:
            server.serve_forever()
        finally:
            server.server_close()

    def shutdown(self) -> None:
        if self._server:
            self._server.shutdown()


def create_console_server(
    config: GuardianConfig | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
) -> ParentConsoleApp:
    resolved = config or load_config()
    if not resolved.database_path.is_file():
        raise GuardianMeshError("Database not initialized. Run 'guardian init' first.")
    return ParentConsoleApp(resolved, host=host, port=port, open_browser=open_browser)


def launch_console(
    config: GuardianConfig | None = None,
    host: str = "127.0.0.1",
    port: int = 8765,
    open_browser: bool = True,
) -> int:
    app = create_console_server(config, host=host, port=port, open_browser=open_browser)
    url = f"http://{host}:{port}/"
    print("GuardianMesh Parent Console")
    print(f"Local URL: {url}")
    print("Press Ctrl+C to stop.")
    if open_browser:
        try:
            webbrowser.open(url, new=2)
        except Exception:
            pass
    try:
        app.serve_forever()
    except KeyboardInterrupt:
        print("\nParent Console stopped.")
    return 0
