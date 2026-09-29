"""Shared slowapi limiter instance.

A single module-level instance so routers (`@limiter.limit(...)`) and the app
factory (registering it on `app.state` + the exception handler) reference the
exact same object.
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
