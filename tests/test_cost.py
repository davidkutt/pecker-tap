import asyncio

import pytest

from pecker_tap.config import Price
from pecker_tap.cost import CallRecord, CostCapReachedError, CostMeter, tokens_cost

PRICE = Price(input_per_mtok=0.30, output_per_mtok=1.20)


def record(cost: float) -> CallRecord:
    return CallRecord(
        note_path="a.md",
        section=0,
        model="m",
        input_tokens=1,
        output_tokens=1,
        cost_usd=cost,
        cost_source="reported",
        latency_s=0.0,
    )


def test_first_call_estimate_is_input_plus_max_output_at_list_price() -> None:
    meter = CostMeter(0.5, PRICE, 4096)
    # 3000 characters -> 1000 input tokens; 4096 output tokens.
    assert meter.first_call_estimate(3000) == pytest.approx((1000 * 0.30 + 4096 * 1.20) / 1e6)
    assert tokens_cost(None, 10, 10) == 0.0


async def test_later_calls_reserve_the_most_expensive_call_so_far() -> None:
    meter = CostMeter(0.5, PRICE, 4096, earlier_calls=[record(0.1), record(0.2)])
    assert meter.spent == pytest.approx(0.3)
    reserved = await meter.reserve(10)
    assert reserved == pytest.approx(0.2)  # 0.3 + 0.2 = 0.5 is still under the cap
    with pytest.raises(CostCapReachedError):
        await meter.reserve(10)  # in-flight reservations count as spent
    meter.settle(reserved, record(0.05))
    with pytest.raises(CostCapReachedError):
        await meter.reserve(10)  # 0.35 + 0.2 > 0.5


async def test_concurrent_reservations_cannot_overshoot() -> None:
    meter = CostMeter(1.0, PRICE, 4096, earlier_calls=[record(0.3)])
    results = await asyncio.gather(*(meter.reserve(1) for _ in range(5)), return_exceptions=True)
    granted = [r for r in results if isinstance(r, float)]
    assert len(granted) == 2  # 0.3 spent + 2 x 0.3 reserved <= 1.0; a third would cross it
