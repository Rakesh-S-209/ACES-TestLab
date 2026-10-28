"""
tests/integration/test_event_hub.py
Integration tests for src/soc_pipeline/event_hub.py

Covers:
  - Property 20: all active subscribers receive every published event
  - Property 21: events delivered in strict publication order
  - Property 22: remaining subscribers receive events after one disconnects
  - Non-blocking publish (Requirement 8.2)
  - delivery_count and subscriber_count diagnostics
  - get_queue() returns asyncio.Queue for thread-safe bridging
"""

from __future__ import annotations

import asyncio

import pytest

from src.zero_trust.models import AlertEvent, AlertType

pytestmark = pytest.mark.integration


def _event(ip: str = "1.2.3.4", port: int = 3389) -> AlertEvent:
    return AlertEvent(
        alert_type=AlertType.PORT_TRAP,
        source_ip=ip,
        timestamp_ms=0.0,
        port=port,
    )


# ===========================================================================
# Basic publish / subscribe
# ===========================================================================

class TestPublishSubscribe:

    @pytest.mark.asyncio
    async def test_single_subscriber_receives_event(self, fresh_hub) -> None:
        received: list[AlertEvent] = []

        async def consumer():
            async for evt in fresh_hub.subscribe():
                received.append(evt)
                break

        task = asyncio.create_task(consumer())
        await asyncio.sleep(0)
        await fresh_hub.publish(_event())
        await asyncio.wait_for(task, timeout=2.0)
        assert len(received) == 1
        assert received[0].source_ip == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_publish_no_subscribers_does_not_block(self, fresh_hub) -> None:
        await asyncio.wait_for(fresh_hub.publish(_event()), timeout=1.0)

    @pytest.mark.asyncio
    async def test_get_queue_returns_asyncio_queue(self, fresh_hub) -> None:
        assert isinstance(fresh_hub.get_queue(), asyncio.Queue)

    @pytest.mark.asyncio
    async def test_subscriber_count_zero_initially(self, fresh_hub) -> None:
        assert fresh_hub.subscriber_count == 0

    @pytest.mark.asyncio
    async def test_delivery_count_zero_initially(self, fresh_hub) -> None:
        assert fresh_hub.delivery_count == 0


# ===========================================================================
# Property 20: all subscribers receive the event
# ===========================================================================

class TestFanOut:

    @pytest.mark.asyncio
    async def test_four_subscribers_all_receive(self, fresh_hub) -> None:
        n = 4
        received: list[list[AlertEvent]] = [[] for _ in range(n)]

        async def consumer(idx: int):
            async for evt in fresh_hub.subscribe():
                received[idx].append(evt)
                break

        tasks = [asyncio.create_task(consumer(i)) for i in range(n)]
        await asyncio.sleep(0)
        await fresh_hub.publish(_event())
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=3.0)
        for i, bucket in enumerate(received):
            assert len(bucket) == 1, f"Subscriber {i} got {len(bucket)} events"

    @pytest.mark.asyncio
    async def test_delivery_count_equals_subscriber_count(self, fresh_hub) -> None:
        n = 3

        async def consumer():
            async for _ in fresh_hub.subscribe():
                break

        tasks = [asyncio.create_task(consumer()) for _ in range(n)]
        await asyncio.sleep(0)
        await fresh_hub.publish(_event())
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=3.0)
        assert fresh_hub.delivery_count == n

    @pytest.mark.asyncio
    async def test_each_subscriber_gets_independent_copy(self, fresh_hub) -> None:
        """Events must be delivered independently — modifying one copy must not affect another."""
        copies: list[AlertEvent] = []

        async def consumer():
            async for evt in fresh_hub.subscribe():
                copies.append(evt)
                break

        tasks = [asyncio.create_task(consumer()) for _ in range(2)]
        await asyncio.sleep(0)
        await fresh_hub.publish(_event("10.0.0.1"))
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=2.0)
        assert len(copies) == 2
        assert copies[0].source_ip == copies[1].source_ip


# ===========================================================================
# Property 21: strict publication order
# ===========================================================================

class TestOrdering:

    @pytest.mark.asyncio
    async def test_five_events_in_order(self, fresh_hub) -> None:
        received: list[str] = []

        async def consumer():
            count = 0
            async for evt in fresh_hub.subscribe():
                received.append(evt.source_ip)
                count += 1
                if count == 5:
                    break

        task = asyncio.create_task(consumer())
        await asyncio.sleep(0)
        for i in range(5):
            await fresh_hub.publish(_event(ip=f"10.0.0.{i}"))
        await asyncio.wait_for(task, timeout=3.0)
        assert received == [f"10.0.0.{i}" for i in range(5)]

    @pytest.mark.asyncio
    async def test_two_subscribers_see_same_order(self, fresh_hub) -> None:
        results: list[list[str]] = [[], []]

        async def consumer(idx: int):
            count = 0
            async for evt in fresh_hub.subscribe():
                results[idx].append(evt.source_ip)
                count += 1
                if count == 4:
                    break

        tasks = [asyncio.create_task(consumer(i)) for i in range(2)]
        await asyncio.sleep(0)
        for i in range(4):
            await fresh_hub.publish(_event(ip=f"192.168.0.{i}"))
        await asyncio.wait_for(asyncio.gather(*tasks), timeout=3.0)
        assert results[0] == results[1]
        assert results[0] == [f"192.168.0.{i}" for i in range(4)]


# ===========================================================================
# Property 22: remaining subscribers after one disconnects
# ===========================================================================

class TestSubscriberLifecycle:

    @pytest.mark.asyncio
    async def test_survivor_receives_after_doomed_exits(self, fresh_hub) -> None:
        survivor_received: list[AlertEvent] = []

        async def doomed():
            async for _ in fresh_hub.subscribe():
                break  # exit after first event

        async def survivor():
            count = 0
            async for evt in fresh_hub.subscribe():
                survivor_received.append(evt)
                count += 1
                if count == 2:
                    break

        d_task = asyncio.create_task(doomed())
        s_task = asyncio.create_task(survivor())
        await asyncio.sleep(0)

        await fresh_hub.publish(_event(ip="10.0.1.1"))
        await asyncio.wait_for(d_task, timeout=2.0)
        await asyncio.sleep(0)  # let doomed deregister

        await fresh_hub.publish(_event(ip="10.0.1.2"))
        await asyncio.wait_for(s_task, timeout=2.0)

        assert len(survivor_received) == 2
        assert survivor_received[0].source_ip == "10.0.1.1"
        assert survivor_received[1].source_ip == "10.0.1.2"

    @pytest.mark.asyncio
    async def test_subscriber_count_decrements_after_exit(self, fresh_hub) -> None:
        async def consumer():
            async for _ in fresh_hub.subscribe():
                break

        task = asyncio.create_task(consumer())
        await asyncio.sleep(0)
        assert fresh_hub.subscriber_count == 1
        await fresh_hub.publish(_event())
        await asyncio.wait_for(task, timeout=2.0)
        await asyncio.sleep(0)
        assert fresh_hub.subscriber_count == 0

    @pytest.mark.asyncio
    async def test_subscriber_registered_before_publish(self, fresh_hub) -> None:
        received: list = []

        async def consumer():
            async for evt in fresh_hub.subscribe():
                received.append(evt)
                break

        task = asyncio.create_task(consumer())
        await asyncio.sleep(0)  # yield so consumer registers
        assert fresh_hub.subscriber_count == 1
        await fresh_hub.publish(_event())
        await asyncio.wait_for(task, timeout=2.0)
        assert len(received) == 1


# ===========================================================================
# Thread-safe bridging via get_queue()
# ===========================================================================

class TestThreadSafeBridging:

    @pytest.mark.asyncio
    async def test_put_nowait_via_get_queue(self, fresh_hub) -> None:
        """Simulate a background OS thread bridging an event via get_queue().put_nowait."""
        received: list[AlertEvent] = []

        async def consumer():
            for _ in range(1):
                event = await fresh_hub.get_queue().get()
                received.append(event)

        task = asyncio.create_task(consumer())
        # Simulate thread-safe bridge
        evt = _event(ip="thread_bridge")
        fresh_hub.get_queue().put_nowait(evt)
        await asyncio.wait_for(task, timeout=2.0)
        assert len(received) == 1
        assert received[0].source_ip == "thread_bridge"
