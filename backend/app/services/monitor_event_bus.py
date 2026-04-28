from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any


@dataclass
class _Subscription:
    user_id: int
    role: str
    monitor_id: int | None
    queue: asyncio.Queue[dict[str, Any]]


class MonitorEventBus:
    def __init__(self) -> None:
        self._subscriptions: list[_Subscription] = []
        self._lock = asyncio.Lock()
        self._loop: asyncio.AbstractEventLoop | None = None

    async def subscribe(self, *, user_id: int, role: str, monitor_id: int | None = None) -> asyncio.Queue[dict[str, Any]]:
        self._loop = asyncio.get_running_loop()
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=100)
        async with self._lock:
            self._subscriptions.append(
                _Subscription(user_id=user_id, role=role, monitor_id=monitor_id, queue=queue)
            )
        return queue

    async def unsubscribe(self, queue: asyncio.Queue[dict[str, Any]]) -> None:
        async with self._lock:
            self._subscriptions = [subscription for subscription in self._subscriptions if subscription.queue is not queue]

    async def publish(self, event: dict[str, Any]) -> None:
        async with self._lock:
            subscriptions = list(self._subscriptions)

        for subscription in subscriptions:
            owner_user_id = event.get("owner_user_id")
            event_monitor_id = event.get("monitor_id")
            if subscription.role != "admin" and subscription.user_id != owner_user_id:
                continue
            if subscription.monitor_id is not None and subscription.monitor_id != event_monitor_id:
                continue
            try:
                subscription.queue.put_nowait(event)
            except asyncio.QueueFull:
                try:
                    subscription.queue.get_nowait()
                except asyncio.QueueEmpty:
                    pass
                try:
                    subscription.queue.put_nowait(event)
                except asyncio.QueueFull:
                    continue

    def publish_sync(self, event: dict[str, Any]) -> None:
        if self._loop is None or self._loop.is_closed():
            return
        asyncio.run_coroutine_threadsafe(self.publish(event), self._loop)


_event_bus = MonitorEventBus()


def get_monitor_event_bus() -> MonitorEventBus:
    return _event_bus
