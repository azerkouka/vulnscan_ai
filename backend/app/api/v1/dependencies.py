"""FastAPI dependency-injection wiring.

Populated in Phase 2 (`get_current_user`, `get_db_session`) and grown as each
use case is added (`get_<use_case>_use_case`). Kept as a single module so all
DI wiring is visible in one place rather than scattered across routers.
"""

from __future__ import annotations
