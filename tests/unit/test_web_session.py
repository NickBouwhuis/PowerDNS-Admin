"""Tests for the server-side session middleware."""
from unittest.mock import patch

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from powerdnsadmin.web.session import ServerSideSessionMiddleware, SessionData


def _make_app():
    app = FastAPI()
    app.add_middleware(ServerSideSessionMiddleware, secret_key="test-secret")

    @app.get("/probe")
    def probe(request: Request):
        # Both access paths must yield the very same session object:
        # app code uses request.state.session, authlib uses request.session.
        same = request.state.session is request.session
        request.session["oauth_state"] = "abc"
        return {"same": same, "modified": request.state.session.modified}

    return app


def test_request_session_is_exposed_in_scope():
    """authlib's Starlette client reads request.session, which requires
    the session to be present in the ASGI scope (regression for OIDC login
    failing with 'SessionMiddleware must be installed')."""
    with patch.object(ServerSideSessionMiddleware, "_save_session") as save:
        client = TestClient(_make_app())
        resp = client.get("/probe")

    assert resp.status_code == 200
    assert resp.json() == {"same": True, "modified": True}
    assert "session" in resp.cookies
    save.assert_called_once()
    saved = save.call_args.args[1]
    assert isinstance(saved, SessionData)
    assert saved["oauth_state"] == "abc"
