"""Caps the size of request bodies, as pure ASGI middleware.

The upload endpoint checks the size of what it reads, but by then the
framework has already received the whole multipart body and spooled it to
disk - a multi-gigabyte upload would be accepted in full just to be refused.
This middleware refuses it at the door instead:

- a request declaring a `Content-Length` over the limit is answered 413
  before a single body byte is read;
- a request that declares nothing (chunked transfer) or lies is cut off as
  soon as the bytes actually received pass the limit.
"""

from __future__ import annotations

import json

from fastapi import HTTPException, status
from starlette.types import ASGIApp, Message, Receive, Scope, Send


class MaxBodySizeMiddleware:
    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self._max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = _declared_length(scope)
        if declared is not None and declared > self._max_bytes:
            await self._reject(send)
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self._max_bytes:
                    # Raised from inside the endpoint's own read of the body.
                    # It has to be FastAPI's HTTPException specifically: any
                    # other exception raised while a body is being parsed is
                    # turned by FastAPI into a generic 400.
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=self._message(),
                    )
            return message

        await self.app(scope, limited_receive, send)

    def _message(self) -> str:
        limit_mb = self._max_bytes / (1024 * 1024)
        return f"The request is larger than the {limit_mb:g} MB allowed."

    async def _reject(self, send: Send) -> None:
        body = json.dumps({"error": {"code": "http_error", "message": self._message()}}).encode()
        await send(
            {
                "type": "http.response.start",
                "status": status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                "headers": [
                    (b"content-type", b"application/json"),
                    (b"content-length", str(len(body)).encode("ascii")),
                    # The body that was announced is not going to be read.
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})


def _declared_length(scope: Scope) -> int | None:
    for name, value in scope.get("headers") or []:
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None
