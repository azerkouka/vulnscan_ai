"""Request-id + timing middleware, as pure ASGI (not `BaseHTTPMiddleware`).

`BaseHTTPMiddleware` (what `@app.middleware("http")` gives you) runs the rest
of the stack in a separate anyio task via a task group. That breaks
SQLAlchemy's async-over-greenlet bridging for any DB session that was created
outside that task (e.g. a session shared across a request via a dependency
override in tests) with a misleading
"Future ... attached to a different loop" RuntimeError. Pure ASGI middleware
wraps `send` directly and never spawns a separate task, so it doesn't have
this problem - this is the documented workaround.
"""

from __future__ import annotations

import time
import uuid
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.logging import get_logger

logger = get_logger(__name__)


class RequestContextMiddleware:
    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers") or [])
        request_id = headers.get(b"x-request-id", b"").decode() or str(uuid.uuid4())
        start = time.perf_counter()
        status_code = 500

        async def send_wrapper(message: Message) -> None:
            nonlocal status_code
            if message["type"] == "http.response.start":
                status_code = message["status"]
                response_headers: list[Any] = list(message.get("headers", []))
                response_headers.append((b"x-request-id", request_id.encode()))
                message["headers"] = response_headers
            await send(message)

        await self.app(scope, receive, send_wrapper)

        duration_ms = round((time.perf_counter() - start) * 1000, 2)
        logger.info(
            "request_completed",
            request_id=request_id,
            method=scope.get("method"),
            path=scope.get("path"),
            status_code=status_code,
            duration_ms=duration_ms,
        )
