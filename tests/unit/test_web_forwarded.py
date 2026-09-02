"""Tests for ForwardedHostMiddleware."""
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from powerdnsadmin.web.forwarded import ForwardedHostMiddleware


def _make_app(trusted="127.0.0.1"):
    app = FastAPI()
    app.add_middleware(ForwardedHostMiddleware, trusted_hosts=trusted)

    @app.get("/cb", name="cb")
    def cb(request: Request):
        return {"url": str(request.url_for("cb")), "host": request.headers["host"]}

    return app


def test_forwarded_headers_from_trusted_proxy_rewrite_url():
    # TestClient's client address is testclient:50000 -> trust it explicitly
    client = TestClient(_make_app(trusted="testclient"), base_url="http://127.0.0.1:9191")
    r = client.get("/cb", headers={
        "X-Forwarded-Host": "dns.example.com",
        "X-Forwarded-Proto": "https",
    })
    assert r.json() == {"url": "https://dns.example.com/cb", "host": "dns.example.com"}


def test_forwarded_host_with_port_and_chain():
    client = TestClient(_make_app(trusted="*"), base_url="http://127.0.0.1:9191")
    r = client.get("/cb", headers={
        "X-Forwarded-Host": "dns.example.com:8443, inner:9191",
        "X-Forwarded-Proto": "https, http",
    })
    assert r.json()["url"] == "https://dns.example.com:8443/cb"


def test_loopback_bound_server_trusts_forwarded_headers_regardless_of_client():
    """Uvicorn rewrites scope['client'] from X-Forwarded-For before we run, so a
    loopback-bound backend must not depend on the client address."""
    app = _make_app(trusted="10.0.0.1")
    client = TestClient(app, base_url="http://127.0.0.1:9191", client=("172.19.0.1", 1234))
    r = client.get("/cb", headers={
        "X-Forwarded-For": "172.19.0.1",
        "X-Forwarded-Host": "dns.example.com",
        "X-Forwarded-Proto": "https",
    })
    assert r.json()["url"] == "https://dns.example.com/cb"


def test_forwarded_headers_ignored_from_untrusted_client():
    client = TestClient(_make_app(trusted="10.0.0.1"), base_url="http://backend.internal:9191")
    r = client.get("/cb", headers={
        "X-Forwarded-Host": "evil.example.com",
        "X-Forwarded-Proto": "https",
    })
    assert r.json() == {"url": "http://backend.internal:9191/cb", "host": "backend.internal:9191"}


def test_no_forwarded_headers_is_noop():
    client = TestClient(_make_app(trusted="*"), base_url="http://127.0.0.1:9191")
    r = client.get("/cb")
    assert r.json()["url"] == "http://127.0.0.1:9191/cb"
