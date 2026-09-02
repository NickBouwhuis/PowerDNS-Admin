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


def test_db_session_released_around_request():
    """The event-loop thread's scoped session must be removed before and
    after each request so it never holds a stale transaction open."""
    with patch.object(ServerSideSessionMiddleware, "_save_session"), \
            patch.object(ServerSideSessionMiddleware, "_release_db_session") as rel:
        TestClient(_make_app()).get("/probe")
    assert rel.call_count == 2


def test_save_session_recovers_from_insert_race():
    from sqlalchemy.exc import IntegrityError
    from unittest.mock import MagicMock

    mw = ServerSideSessionMiddleware(app=None, secret_key="x")
    fake_db = MagicMock()
    fake_db.session.query.return_value.filter_by.return_value.first.return_value = None
    fake_db.session.commit.side_effect = [IntegrityError("s", {}, Exception("dup")), None]
    with patch.dict("sys.modules", {"powerdnsadmin.models.base": MagicMock(db=fake_db)}):
        mw._save_session("sid", SessionData({"a": 1}))
    fake_db.session.rollback.assert_called_once()
    fake_db.session.query.return_value.filter_by.return_value.update.assert_called_once()
    assert fake_db.session.commit.call_count == 2
