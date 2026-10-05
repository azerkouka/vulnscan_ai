"""Security response headers, as pure ASGI middleware (see `app.core.middleware`
for why not `BaseHTTPMiddleware`).

The API only ever returns JSON or file downloads, never a page, so its
policy can be as strict as policies get: nothing may be loaded, framed or
sniffed. The interactive API docs are the one exception - Swagger UI is an
HTML page that loads its script from a CDN - so the content policy is not
applied to them (they are switched off entirely in production).
"""

from __future__ import annotations

from starlette.types import ASGIApp, Message, Receive, Scope, Send

_DOCS_PATHS = frozenset({"/docs", "/redoc", "/openapi.json", "/docs/oauth2-redirect"})

_BASE_HEADERS: list[tuple[bytes, bytes]] = [
    # Don't let a browser guess a content type other than the declared one.
    (b"x-content-type-options", b"nosniff"),
    # The API has no page worth embedding; refuse being framed (clickjacking).
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
    (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
    (b"cross-origin-resource-policy", b"same-site"),
]
_CONTENT_POLICY = (b"content-security-policy", b"default-src 'none'; frame-ancestors 'none'")
# Responses carry reports and account data: keep them out of shared and disk caches.
_NO_STORE = (b"cache-control", b"no-store")
_HSTS = (b"strict-transport-security", b"max-age=31536000; includeSubDomains")


class SecurityHeadersMiddleware:
    def __init__(self, app: ASGIApp, *, hsts: bool = False) -> None:
        """`hsts`: only where the API is really served over HTTPS - sent
        over plain HTTP it is ignored, but on a mixed setup it would pin
        browsers to HTTPS for a host that can't serve it."""
        self.app = app
        self._hsts = hsts

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        is_docs = scope.get("path", "") in _DOCS_PATHS

        async def send_with_headers(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers: list[tuple[bytes, bytes]] = list(message.get("headers", []))
                present = {name.lower() for name, _ in headers}
                additions = list(_BASE_HEADERS)
                if not is_docs:
                    additions += [_CONTENT_POLICY, _NO_STORE]
                if self._hsts:
                    additions.append(_HSTS)
                # Never override a header an endpoint set on purpose.
                headers += [header for header in additions if header[0] not in present]
                message["headers"] = headers
            await send(message)

        await self.app(scope, receive, send_with_headers)
