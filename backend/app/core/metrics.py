from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass
from threading import Lock


@dataclass
class TimerMetric:
    count: int = 0
    total_ms: float = 0.0


class MetricsRegistry:
    def __init__(self) -> None:
        self._timers: dict[str, TimerMetric] = defaultdict(TimerMetric)
        self._counters: dict[str, int] = defaultdict(int)
        self._lock = Lock()

    def record_timing(self, name: str, duration_ms: float) -> None:
        with self._lock:
            metric = self._timers[name]
            metric.count += 1
            metric.total_ms += duration_ms

    def increment(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] += amount

    def snapshot(self) -> dict[str, dict[str, float | int]]:
        with self._lock:
            timers = {
                name: {
                    "count": metric.count,
                    "avg_ms": round(metric.total_ms / metric.count, 2) if metric.count else 0.0,
                    "total_ms": round(metric.total_ms, 2),
                }
                for name, metric in self._timers.items()
            }
            counters = {name: {"count": value} for name, value in self._counters.items()}
        return {"timers": timers, "counters": counters}


metrics_registry = MetricsRegistry()
