import asyncio


class Broadcaster:
    def __init__(self):
        self._subscribers: set[asyncio.Queue] = set()

    async def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue()
        self._subscribers.add(q)
        return q

    def unsubscribe(self, q: asyncio.Queue):
        self._subscribers.discard(q)

    async def publish(self, message: dict):
        for q in list(self._subscribers):
            await q.put(message)


broadcaster = Broadcaster()
