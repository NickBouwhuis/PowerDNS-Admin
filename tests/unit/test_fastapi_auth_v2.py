"""Unit tests for the API v2 auth registration endpoint.

Covers powerdnsadmin/api/v2/auth.py::register — the endpoint the SPA's
register page calls. Previously the SPA POSTed to ``/register`` (a Next.js
page route, not proxied to the backend), which surfaced a confusing
"Failed to find Server Action" error. These tests pin the JSON contract.

Route handlers use deferred imports, so Setting/User are patched at their
*source* module paths.
"""
from unittest.mock import MagicMock, patch

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from powerdnsadmin.api.v2.auth import router as auth_router

_SETTING = "powerdnsadmin.models.setting.Setting"
_USER = "powerdnsadmin.models.user.User"
_SEND_EMAIL = "powerdnsadmin.services.email.send_account_verification"


@pytest.fixture(scope="module")
def client():
    app = FastAPI()
    app.include_router(auth_router)
    return TestClient(app, raise_server_exceptions=False)


def _settings(**overrides):
    """Build a Setting mock whose .get() reads from a defaults dict."""
    defaults = {
        "signup_enabled": True,
        "local_db_enabled": True,
        "verify_user_email": False,
    }
    defaults.update(overrides)
    inst = MagicMock()
    inst.get.side_effect = lambda key: defaults.get(key)
    factory = MagicMock(return_value=inst)
    return factory


class TestRegister:
    def test_signup_disabled_returns_403(self, client):
        with patch(_SETTING, _settings(signup_enabled=False)):
            resp = client.post("/auth/register", json={
                "username": "alice", "password": "pw", "rpassword": "pw",
            })
        assert resp.status_code == 403
        assert "disabled" in resp.json()["detail"].lower()

    def test_local_db_disabled_returns_400(self, client):
        with patch(_SETTING, _settings(local_db_enabled=False)):
            resp = client.post("/auth/register", json={
                "username": "alice", "password": "pw", "rpassword": "pw",
            })
        assert resp.status_code == 400

    def test_password_mismatch_returns_400(self, client):
        with patch(_SETTING, _settings()):
            resp = client.post("/auth/register", json={
                "username": "alice", "password": "pw", "rpassword": "nope",
            })
        assert resp.status_code == 400
        assert "match" in resp.json()["detail"].lower()

    def test_successful_registration(self, client):
        user = MagicMock()
        user.create_local_user.return_value = {"status": True, "msg": "ok"}
        with patch(_SETTING, _settings()), \
                patch(_USER, MagicMock(return_value=user)):
            resp = client.post("/auth/register", json={
                "username": "alice", "password": "pw", "rpassword": "pw",
                "email": "alice@example.com",
            })
        assert resp.status_code == 201
        assert resp.json()["status"] == "ok"
        user.create_local_user.assert_called_once()

    def test_duplicate_user_returns_400(self, client):
        user = MagicMock()
        user.create_local_user.return_value = {
            "status": False, "msg": "Username is already in use"}
        with patch(_SETTING, _settings()), \
                patch(_USER, MagicMock(return_value=user)):
            resp = client.post("/auth/register", json={
                "username": "alice", "password": "pw", "rpassword": "pw",
            })
        assert resp.status_code == 400
        assert "already in use" in resp.json()["detail"]

    def test_email_verification_sends_mail(self, client):
        user = MagicMock()
        user.email = "alice@example.com"
        user.create_local_user.return_value = {"status": True, "msg": "ok"}
        with patch(_SETTING, _settings(verify_user_email=True)), \
                patch(_USER, MagicMock(return_value=user)), \
                patch(_SEND_EMAIL) as send_mail:
            resp = client.post("/auth/register", json={
                "username": "alice", "password": "pw", "rpassword": "pw",
                "email": "alice@example.com",
            })
        assert resp.status_code == 201
        assert resp.json()["status"] == "confirmation_required"
        send_mail.assert_called_once_with("alice@example.com")

    def test_email_required_when_verification_enabled(self, client):
        with patch(_SETTING, _settings(verify_user_email=True)):
            resp = client.post("/auth/register", json={
                "username": "alice", "password": "pw", "rpassword": "pw",
            })
        assert resp.status_code == 400
        assert "email" in resp.json()["detail"].lower()
