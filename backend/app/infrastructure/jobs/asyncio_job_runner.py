"""In-process `JobRunner`: each scan analysis is an asyncio task on the
API's own event loop.

Chosen over a broker-backed queue (Celery/RQ + Redis) because the work is
I/O-bound waiting on a single local LLM, which gains nothing from more
worker processes, and it keeps the stack to the services already in
docker-compose. The trade-off is that jobs live and die with the process:
a restart loses whatever was queued or running, which is why startup marks
such scans FAILED (`FailInterruptedScansUseCase`) instead of leaving them
RUNNING forever. Swapping in a durable queue later only means another
adapter for the same port.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from uuid import UUID

from app.core.logging import get_logger
from app.domain.ports.job_runner import JobRunner

logger = get_logger(__name__)


class AsyncioJobRunner(JobRunner):
    def __init__(
        self, run_scan: Callable[[UUID], Awaitable[None]], *, max_concurrent_jobs: int = 1
    ) -> None:
        """`run_scan` does the actual work for one scan id and owns its own
        resources (DB session, adapters); it is built by the composition
        root, so this class knows nothing about scans beyond their id."""
        self._run_scan = run_scan
        # One local model serves every job: running more analyses at once
        # than it can take only makes each of them slower and likelier to time out.
        self._semaphore = asyncio.Semaphore(max_concurrent_jobs)
        # Strong references: the event loop itself only keeps weak ones, and a
        # task with no other referent can be garbage-collected mid-flight.
        self._tasks: set[asyncio.Task[None]] = set()

    async def enqueue_scan(self, scan_id: UUID) -> None:
        task = asyncio.create_task(self._run(scan_id), name=f"scan-{scan_id}")
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _run(self, scan_id: UUID) -> None:
        async with self._semaphore:
            logger.info("scan_job_started", scan_id=str(scan_id))
            try:
                await self._run_scan(scan_id)
            except Exception:
                # Nobody awaits this task, so an escaping exception would
                # only surface as a "never retrieved" warning at exit.
                logger.exception("scan_job_crashed", scan_id=str(scan_id))
            else:
                logger.info("scan_job_finished", scan_id=str(scan_id))

    async def wait_idle(self) -> None:
        """Waits for every job enqueued so far (and any they enqueue)."""
        while self._tasks:
            await asyncio.gather(*self._tasks, return_exceptions=True)

    async def shutdown(self) -> None:
        for task in self._tasks:
            task.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
