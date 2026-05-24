"""tools/event_loop.py — Module-level persistent asyncio event loop singleton.

Prevents "coroutine never awaited" errors and loop-leak warnings by running
a single daemon thread with ``loop.run_forever()``.  Coroutines are submitted
via ``asyncio.run_coroutine_threadsafe()``.

Usage::

    from tools.event_loop import get_shared_loop

    loop = get_shared_loop()
    future = asyncio.run_coroutine_threadsafe(my_coro(), loop)
    result = future.result(timeout=30)
"""

from __future__ import annotations

import asyncio
import atexit
import logging
import threading
from typing import Optional

logger = logging.getLogger("elengenix.event_loop")

_loop: Optional[asyncio.AbstractEventLoop] = None
_lock: threading.Lock = threading.Lock()
_thread: Optional[threading.Thread] = None


def _run_forever(loop: asyncio.AbstractEventLoop) -> None:
    """Target for the daemon thread — runs the loop until interpreter exit."""
    asyncio.set_event_loop(loop)
    try:
        loop.run_forever()
    except Exception:
        logger.debug("Shared event loop stopped.")


def _cleanup() -> None:
    """Cleanup registered via ``atexit`` — called on interpreter shutdown."""
    global _loop
    if _loop is not None and not _loop.is_closed():
        try:
            _loop.call_soon_threadsafe(_loop.stop)
        except Exception:
            pass


def get_shared_loop() -> asyncio.AbstractEventLoop:
    """Get or create the module-level persistent event loop (thread-safe)."""
    global _loop, _thread
    with _lock:
        if _loop is None:
            _loop = asyncio.new_event_loop()
            _thread = threading.Thread(
                target=_run_forever,
                args=(_loop,),
                daemon=True,
                name="elengenix-event-loop",
            )
            _thread.start()
            atexit.register(_cleanup)
        return _loop
