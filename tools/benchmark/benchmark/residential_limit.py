"""Max-1 concurrent residential Oxylabs dial guard (VAL-BENCH-011).

Live residential basecrawl profiles must never open parallel multi-URL
storm dials through the commercial residential proxy. Soft/direct paths
do not acquire this lock.
"""

from __future__ import annotations

import threading
import time
from contextlib import contextmanager
from typing import Iterator, Optional

# Module-level mutex shared by all adapter instances in-process.
_RESIDENTIAL_LOCK = threading.Lock()
_HOLDER: Optional[str] = None
_ACQUIRED_AT: Optional[float] = None


class ResidentialConcurrencyError(RuntimeError):
    """Raised when a second concurrent residential dial is refused."""

    def __init__(self, detail: str = "residential concurrency > 1 refused") -> None:
        super().__init__(detail)
        self.error_class = "policy_skip"
        self.challenge_class = "hard_optional_skipped"


@contextmanager
def residential_slot(
    *,
    owner: str = "basecrawl-adapter",
    blocking: bool = False,
    timeout: Optional[float] = None,
) -> Iterator[None]:
    """Acquire the global residential dial slot.

    Parameters
    ----------
    owner:
        Diagnostic label (never a secret).
    blocking:
        When False (default), refuse immediately if the slot is held.
        When True, wait up to ``timeout`` seconds (or forever if None).
    timeout:
        Only used when ``blocking`` is True.
    """
    global _HOLDER, _ACQUIRED_AT

    acquired = False
    if blocking:
        if timeout is None:
            acquired = _RESIDENTIAL_LOCK.acquire()
        else:
            acquired = _RESIDENTIAL_LOCK.acquire(timeout=timeout)
    else:
        acquired = _RESIDENTIAL_LOCK.acquire(blocking=False)

    if not acquired:
        raise ResidentialConcurrencyError(
            f"refusing concurrent residential dial (holder={_HOLDER!r}, owner={owner!r}); "
            "live Oxylabs profile concurrency max is 1"
        )

    _HOLDER = owner
    _ACQUIRED_AT = time.monotonic()
    try:
        yield
    finally:
        _HOLDER = None
        _ACQUIRED_AT = None
        _RESIDENTIAL_LOCK.release()


def residential_slot_held() -> bool:
    """Return True if the residential slot is currently acquired."""
    return _RESIDENTIAL_LOCK.locked()


def residential_holder() -> Optional[str]:
    return _HOLDER


def reset_residential_slot_for_tests() -> None:
    """Test-only helper to force-clear a stuck lock after injection failures."""
    global _HOLDER, _ACQUIRED_AT
    # If locked, release once (best-effort). Tests own the process.
    if _RESIDENTIAL_LOCK.locked():
        try:
            _RESIDENTIAL_LOCK.release()
        except RuntimeError:
            pass
    _HOLDER = None
    _ACQUIRED_AT = None
