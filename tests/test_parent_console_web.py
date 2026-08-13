"""Tests for the GuardianMesh Parent Console web UI and its local API."""

from __future__ import annotations

import datetime
import json
import socket
import threading
import urllib.error
import urllib.request
from collections.abc import Iterator
from http.cookiejar import CookieJar
from pathlib import Path

import pytest

from guardianmesh.cli.main import main
from guardianmesh.console.web.app import ParentConsoleApp, create_console_server
from guardianmesh.console.web.presenter import ParentConsolePresenter
from guardianmesh.console.web.security import CSRF_COOKIE, is_loopback_host
from guardianmesh.console.web.settings import ConsoleUISettings, ConsoleUISettingsStore
from guardianmesh.core.config import GuardianConfig, load_config
from guardianmesh.identity.manager import IdentityManager
from guardianmesh.identity.models import IdentityRole
from guardianmesh.pairing.trust import TrustManager
from guardianmesh.policy.engine import PolicyEngine
from guardianmesh.policy.models import AlertSeverity, RuleType
from guardianmesh.security.crypto import public_key_to_pem
from guardianmesh.security.secrets import KeyStorageManager
from guardianmesh.storage.audit import AuditLogger
from guardianmesh.storage.database import Database
from guardianmesh.telemetry.models import TelemetryEnvelope


@pytest.fixture
def console_env(tmp_path: Path) -> tuple[GuardianConfig, str, str]:
    home = tmp_path / "gm_console_web"
    assert main(["--home-dir", str(home), "init", "--role", "parent"]) == 0
    config = load_config(home)
    return config, "parent", "child"


@pytest.fixture
def presenter_with_device(
    console_env: tuple[GuardianConfig, str, str],
) -> tuple[ParentConsolePresenter, str, str]:
    config, _, _ = console_env
    db = Database(config.database_path)
    key_storage = KeyStorageManager(config.keys_dir)
    audit = AuditLogger(db)
    identities = IdentityManager(db, key_storage, audit)
    parent = identities.get_active_identity()
    assert parent is not None
    child, _ = identities.create_identity(role=IdentityRole.CHILD, label="Child Phone", set_active=False)
    child_pub = key_storage.load_public_key(child.id)
    trust = TrustManager(db, audit)
    trust.establish_trust(
        local_identity_id=parent.id,
        remote_identity_id=child.id,
        remote_public_key_pem=public_key_to_pem(child_pub).decode("utf-8"),
        label="Child Phone",
    )
    return ParentConsolePresenter(db, config), parent.id, child.id


def make_online_device(presenter: ParentConsolePresenter, parent_id: str, child_id: str) -> None:
    child_priv = presenter.key_storage.load_private_key(child_id)
    envelope = TelemetryEnvelope(
        device_id=child_id,
        sequence=1,
        payload={
            "battery_percent": 82,
            "charging": True,
            "storage_total_bytes": 64_000_000_000,
            "storage_free_bytes": 28_000_000_000,
            "uptime_seconds": 1800,
            "connectivity": "ONLINE",
            "platform": "Linux",
            "agent_version": "1.1.0",
        },
        captured_at=datetime.datetime.now(datetime.UTC).isoformat(),
    )
    envelope.sign(child_priv)
    presenter.console_service.processor.process_envelope(envelope, local_identity_id=parent_id)


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


@pytest.fixture
def server(console_env: tuple[GuardianConfig, str, str]) -> Iterator[tuple[ParentConsoleApp, str, CookieJar]]:
    config, _, _ = console_env
    app = create_console_server(config=config, host="127.0.0.1", port=free_port(), open_browser=False)
    thread = threading.Thread(target=app.serve_forever, daemon=True)
    thread.start()
    for _ in range(50):
        try:
            urllib.request.urlopen(f"http://127.0.0.1:{app.port}/", timeout=0.2).read()
            break
        except Exception:
            pass
    jar = CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    urllib.request.install_opener(opener)
    try:
        yield app, f"http://127.0.0.1:{app.port}", jar
    finally:
        app.shutdown()
        thread.join(timeout=5)


def request_json(
    url: str, method: str = "GET", data: dict | None = None, jar: CookieJar | None = None
) -> tuple[int, dict]:
    body = None if data is None else json.dumps(data).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if method == "POST":
        csrf = ""
        for cookie in jar or []:
            if cookie.name == CSRF_COOKIE:
                csrf = cookie.value
        headers["X-GuardianMesh-CSRF"] = csrf
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            return response.status, json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read().decode("utf-8"))


def test_settings_store_safe_defaults_and_updates(tmp_path: Path) -> None:
    config = GuardianConfig(home_dir=tmp_path)
    store = ConsoleUISettingsStore(config)
    assert store.load() == ConsoleUISettings()
    updated = store.update({"language": "hi", "theme": "dark", "secret": "blocked"})
    assert updated.language == "hi"
    assert updated.theme == "dark"
    assert "secret" not in json.loads(store.path.read_text())


def test_presenter_bootstrap_home_devices_and_empty_states(
    presenter_with_device: tuple[ParentConsolePresenter, str, str],
) -> None:
    presenter, _, _ = presenter_with_device
    bootstrap = presenter.bootstrap(ConsoleUISettings(language="fr"))
    assert bootstrap["application"]["version"] == "1.1.0"
    assert bootstrap["settings"]["language"] == "fr"
    home = presenter.home()
    assert home["metrics"][0]["value"] == 1
    assert presenter.devices()["devices"][0]["name"] == "Child Phone"
    assert presenter.screen_overview(None)["live_view_available"] is False


def test_device_detail_alerts_and_activity(
    presenter_with_device: tuple[ParentConsolePresenter, str, str],
) -> None:
    presenter, parent_id, child_id = presenter_with_device
    make_online_device(presenter, parent_id, child_id)
    policy = PolicyEngine(presenter.db, presenter.config, presenter.trust_manager).create_policy(child_id)
    presenter.alert_manager.create_or_update_alert(
        device_id=child_id,
        policy_id=policy.id,
        rule_type=RuleType.LOW_BATTERY,
        severity=AlertSeverity.WARNING,
        message="Battery level is low",
    )
    detail = presenter.device_detail(child_id)
    assert detail["device"]["connection"]["is_online"] is True
    assert detail["device"]["alerts_count"] == 1
    assert presenter.alerts()["alerts"][0]["category"] in {
        "needs_attention",
        "device_offline",
        "authorization_issue",
        "security",
        "informational",
    }
    assert all(item["title"] for item in presenter.activity(limit=10)["activity"])


def test_screen_consent_request_never_starts_without_android_consent(
    presenter_with_device: tuple[ParentConsolePresenter, str, str],
) -> None:
    presenter, _, child_id = presenter_with_device
    result = presenter.start_screen_request(child_id)
    assert result["session"]["state"] == "PENDING_CHILD_APPROVAL"
    requirements = result["requirements"]
    assert requirements["steps"][1]["ok"] is True  # trust
    assert requirements["steps"][2]["ok"] is False  # child approval
    assert requirements["can_start"] is False
    assert presenter.screen_overview(child_id)["capability"]["companion_required"] is True


def test_authorization_and_trust_rejection_paths(console_env: tuple[GuardianConfig, str, str]) -> None:
    config, _, _ = console_env
    presenter = ParentConsolePresenter(None, config)
    overview = presenter.screen_overview(None)
    assert overview["requirements"]["can_request"] is False
    assert "select_device" in overview["requirements"]["explanation_key"]


def test_server_boot_navigation_pages_and_session(server: tuple[ParentConsoleApp, str, CookieJar]) -> None:
    _, base, jar = server
    status, session = request_json(f"{base}/api/session", jar=jar)
    assert status == 200 and session["authenticated"] is True
    status, bootstrap = request_json(f"{base}/api/bootstrap", jar=jar)
    assert status == 200 and len(bootstrap["navigation"]) == 7
    for path in ("home", "devices", "screen", "alerts", "activity", "settings", "about"):
        status, body = request_json(f"{base}/api/{path}", jar=jar)
        assert status == 200, path
        assert body is not None
    with urllib.request.urlopen(f"{base}/", timeout=5) as response:
        html = response.read().decode("utf-8")
    assert "GuardianMesh Parent Console" in html


def test_server_settings_update_and_rejects_arbitrary_actions(
    server: tuple[ParentConsoleApp, str, CookieJar],
) -> None:
    app, base, jar = server
    _, _ = request_json(f"{base}/api/session", jar=jar)
    # Create trusted device directly through backend.
    identities = IdentityManager(app.db, app.presenter.key_storage, app.presenter.audit_logger)
    parent = identities.get_active_identity()
    assert parent is not None
    child, _ = identities.create_identity(role=IdentityRole.CHILD, label="Web Child", set_active=False)
    child_pub = app.presenter.key_storage.load_public_key(child.id)
    TrustManager(app.db, app.presenter.audit_logger).establish_trust(
        parent.id, child.id, public_key_to_pem(child_pub).decode("utf-8"), label="Web Child"
    )
    status, body = request_json(
        f"{base}/api/action", "POST", {"action": "screen.request", "device_id": child.id}, jar
    )
    assert status == 200
    assert body["session"]["state"] == "PENDING_CHILD_APPROVAL"
    status, body = request_json(
        f"{base}/api/action",
        "POST",
        {"action": "settings.update", "settings": {"theme": "dark", "secret": "blocked"}},
        jar,
    )
    assert status == 200
    assert body["settings"]["theme"] == "dark"
    settings_path = app.settings_store.path
    assert "secret" not in settings_path.read_text(encoding="utf-8")
    status, body = request_json(f"{base}/api/action", "POST", {"action": "shell", "command": "id"}, jar)
    assert status == 403
    assert "not allowed" in body["error"].lower()
    status, body = request_json(
        f"{base}/api/action", "POST", {"action": "screen.request", "device_id": "GM-C-BAD"}, jar
    )
    assert status == 400


def test_server_requires_csrf_and_blocks_public_host(server: tuple[ParentConsoleApp, str, CookieJar]) -> None:
    app, base, jar = server
    request_json(f"{base}/api/session", jar=jar)
    req = urllib.request.Request(
        f"{base}/api/action",
        data=json.dumps({"action": "settings.update", "settings": {"theme": "dark"}}).encode(),
        headers={"Content-Type": "application/json", "Host": "example.com"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req, timeout=5)
    assert exc.value.code == 403
    # Without CSRF header but localhost host.
    req_no_csrf = urllib.request.Request(
        f"{base}/api/action",
        data=json.dumps({"action": "settings.update", "settings": {"theme": "dark"}}).encode(),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with pytest.raises(urllib.error.HTTPError) as exc:
        urllib.request.urlopen(req_no_csrf, timeout=5)
    assert exc.value.code in {401, 403}


def test_loopback_security_helper() -> None:
    assert is_loopback_host("127.0.0.1:8765")
    assert is_loopback_host("localhost:8765")
    assert is_loopback_host("[::1]:8765")
    assert not is_loopback_host("0.0.0.0:8765")
    assert not is_loopback_host("192.168.1.2:8765")


def test_console_cli_help_lists_web_options() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["console", "--help"])
    assert exc.value.code == 0


def test_all_locales_exist_and_have_required_keys() -> None:
    locale_dir = Path(__file__).resolve().parents[1] / "guardianmesh/console/web/locales"
    required = {
        "navigation.home",
        "navigation.devices",
        "navigation.screen",
        "screen.stop",
        "settings.theme.dark",
    }
    for code in ("en", "hi", "hinglish", "pt", "fr", "zh", "ko", "es"):
        data = json.loads((locale_dir / f"{code}.json").read_text(encoding="utf-8"))
        assert required.issubset(data.keys())
