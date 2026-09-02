"""ASGI middleware honoring X-Forwarded-Host / X-Forwarded-Proto.

The FastAPI backend is not user-facing: it sits behind the Next.js server
(and usually a reverse proxy in front of that). Next.js rewrites the request
with ``Host: 127.0.0.1:9191`` but forwards the original host and scheme in
``X-Forwarded-Host`` / ``X-Forwarded-Proto``. Uvicorn's own proxy-headers
handling only applies ``X-Forwarded-Proto`` and ``X-Forwarded-For``, so
without this middleware ``request.url_for(...)`` (used for OAuth/OIDC/SAML
redirect URIs) points at the internal address.

Forwarded headers are only trusted when the direct client is in
``FORWARDED_ALLOW_IPS`` (comma separated, default ``127.0.0.1``, ``*`` for
any) — the same setting Uvicorn/Gunicorn use.
"""
import os


class ForwardedHostMiddleware:
    def __init__(self, app, trusted_hosts: str | None = None):
        self.app = app
        raw = trusted_hosts if trusted_hosts is not None else os.getenv(
            "FORWARDED_ALLOW_IPS", "127.0.0.1")
        self.trust_all = raw.strip() == "*"
        self.trusted = {h.strip() for h in raw.split(",") if h.strip()}

    def _is_trusted(self, scope) -> bool:
        if self.trust_all:
            return True
        client = scope.get("client")
        return bool(client) and client[0] in self.trusted

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket") and self._is_trusted(scope):
            headers = dict(scope["headers"])
            fwd_host = headers.get(b"x-forwarded-host")
            fwd_proto = headers.get(b"x-forwarded-proto")

            if fwd_host:
                # Use the first value if the proxy chain appended several.
                host = fwd_host.split(b",")[0].strip()
                if host:
                    scope["headers"] = [
                        (k, v) for k, v in scope["headers"] if k != b"host"
                    ] + [(b"host", host)]
                    hostname, _, port = host.decode("latin-1").rpartition(":")
                    if hostname and port.isdigit():
                        scope["server"] = (hostname, int(port))
                    else:
                        scope["server"] = (host.decode("latin-1"), None)

            if fwd_proto:
                proto = fwd_proto.split(b",")[0].strip().decode("latin-1")
                if proto in ("http", "https"):
                    scope["scheme"] = proto if scope["type"] == "http" else (
                        "wss" if proto == "https" else "ws")

        await self.app(scope, receive, send)
