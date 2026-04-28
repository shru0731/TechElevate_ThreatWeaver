from __future__ import annotations

import time
from collections.abc import Callable
from typing import TypeVar


T = TypeVar("T")


def retry_operation(
    operation: Callable[[], T],
    *,
    retries: int,
    delay_seconds: float = 0.0,
    retryable_exceptions: tuple[type[BaseException], ...] = (Exception,),
) -> T:
    attempts = max(1, retries + 1)
    last_error: BaseException | None = None

    for attempt in range(attempts):
        try:
            return operation()
        except retryable_exceptions as exc:
            last_error = exc
            if attempt == attempts - 1:
                raise
            if delay_seconds > 0:
                time.sleep(delay_seconds)

    if last_error is not None:
        raise last_error
    raise RuntimeError("retry_operation exhausted without a result")
