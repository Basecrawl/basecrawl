"""Max concurrent Firecrawl cloud scrapes (account plan limit).

Hobby / free accounts advertise a parallel scrape ceiling of **2**
(``firecrawl --status`` concurrency jobs). Multi-URL adapter runs must
not open unbounded parallel scrapes (VAL-BENCH-012). Preferred operator
default is 1; hard ceiling is 2.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Iterator, Optional

# Plan concurrent-request ceiling for this mission's Firecrawl account class.
FIRECRAWL_MAX_CONCURRENCY = 2

_SLOT = threading.BoundedSemaphore(FIRECRAWL_MAX_CONCURRENCY)
_ACTIVE = 0
_ACTIVE_LOCK = threading.Lock()
_HOLDERS: set[str] = set()


class FirecrawlConcurrencyError(RuntimeError):
    """Raised when a scrape would exceed the documented concurrency ceiling."""

    def __init__(
        self,
        detail: str = "firecrawl concurrency limit reached",
    ) -> None:
        super().__init__(detail)
        self.error_class = "policy_skip"
        self.challenge_class = "hard_optional_skipped"


@contextmanager
def firecrawl_slot(
    *,
    owner: str = "firecrawl-adapter",
    blocking: bool = True,
    timeout: Optional[float] = None,
) -> Iterator[None]:
    """Acquire one of the at-most-2 concurrent Firecrawl scrape slots.

    Parameters
    ----------
    owner:
        Diagnostic label (never a secret).
    blocking:
        When True (default), wait for a free slot (optional ``timeout``).
        When False, refuse immediately if both slots are held.
    timeout:
        Seconds to wait when ``blocking`` is True; ``None`` waits forever.
    """
    global _ACTIVE

    acquired = False
    if blocking:
        if timeout is None:
            acquired = _SLOT.acquire()
        else:
            acquired = _SLOT.acquire(timeout=timeout)
    else:
        acquired = _SLOT.acquire(blocking=False)

    if not acquired:
        with _ACTIVE_LOCK:
            holders = sorted(_HOLDERS)
            active = _ACTIVE
        raise FirecrawlConcurrencyError(
            f"refusing Firecrawl scrape exceeding concurrency "
            f"{FIRECRAWL_MAX_CONCURRENCY} (active={active}, holders={holders!r}, "
            f"owner={owner!r})"
        )

    with _ACTIVE_LOCK:
        _ACTIVE += 1
        _HOLDERS.add(owner)
    try:
        yield
    finally:
        with _ACTIVE_LOCK:
            _ACTIVE = max(0, _ACTIVE - 1)
            _HOLDERS.discard(owner)
        _SLOT.release()


def firecrawl_active_count() -> int:
    with _ACTIVE_LOCK:
        return _ACTIVE


def firecrawl_holders() -> set[str]:
    with _ACTIVE_LOCK:
        return set(_HOLDERS)


def reset_firecrawl_slots_for_tests() -> None:
    """Test-only helper: drain active holders and rebuild the semaphore."""
    global _SLOT, _ACTIVE, _HOLDERS
    # Best-effort: if tests leak slots, rebuild rather than hang later.
    with _ACTIVE_LOCK:
        # Drain existing semaphore permits then recreate full capacity.
        while _SLOT.acquire(blocking=False):
            pass
        _SLOT = threading.BoundedSemaphore(FIRECRAWL_MAX_CONCURRENCY)
        _ACTIVE = 0
        _HOLDERS = set()
    # Touch time for coverage of any future ages.
    _ = time.monotonic()
