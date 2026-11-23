"""Cost cap for model calls (spec, Model and settings; V1 brief, deliverable 10).

Before every call the meter reserves an amount and refuses the call if spent plus reserved would
cross the cap. The reservation is the most expensive call so far; before the first call of a run
it is the prompt's input tokens plus the maximum output tokens at list price. Input tokens are
estimated generously (one token per three characters). After the call the reservation is replaced
by the cost OpenRouter reports, or by tokens times list price when no cost comes back.

Calls run concurrently, so reservations of calls still in flight count as spent.
"""

from __future__ import annotations

import asyncio
import math
from collections.abc import Iterable
from typing import Literal

from pydantic import BaseModel, ConfigDict

from pecker_tap.config import Price

CHARS_PER_TOKEN_ESTIMATE = 3


class CallRecord(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    note_path: str
    section: int
    model: str
    input_tokens: int
    output_tokens: int
    cost_usd: float
    cost_source: Literal["reported", "estimated"]
    latency_s: float


class CostCapReachedError(RuntimeError):
    """The next call could cross the cost cap; nothing was sent."""


def tokens_cost(price: Price | None, input_tokens: int, output_tokens: int) -> float:
    if price is None:
        return 0.0
    return (input_tokens * price.input_per_mtok + output_tokens * price.output_per_mtok) / 1e6


class CostMeter:
    def __init__(
        self,
        cap_usd: float,
        price: Price | None,
        max_output_tokens: int,
        earlier_calls: Iterable[CallRecord] = (),
    ) -> None:
        self.cap_usd = cap_usd
        self.price = price
        self.max_output_tokens = max_output_tokens
        self.calls: list[CallRecord] = list(earlier_calls)
        self._pending = 0.0
        self._lock = asyncio.Lock()

    @property
    def spent(self) -> float:
        return sum(call.cost_usd for call in self.calls)

    @property
    def max_call(self) -> float:
        return max((call.cost_usd for call in self.calls), default=0.0)

    def first_call_estimate(self, prompt_chars: int) -> float:
        input_tokens = math.ceil(prompt_chars / CHARS_PER_TOKEN_ESTIMATE)
        return tokens_cost(self.price, input_tokens, self.max_output_tokens)

    async def reserve(self, prompt_chars: int) -> float:
        """Reserve the cost of the next call or raise ``CostCapReachedError``."""
        async with self._lock:
            amount = self.max_call if self.calls else self.first_call_estimate(prompt_chars)
            if self.spent + self._pending + amount > self.cap_usd:
                msg = (
                    f"the next model call could cross the cost cap of {self.cap_usd:.2f} USD "
                    f"(spent {self.spent:.4f} USD)"
                )
                raise CostCapReachedError(msg)
            self._pending += amount
            return amount

    def settle(self, reserved: float, record: CallRecord | None) -> None:
        """Replace a reservation with the call's real cost (``None`` if nothing was charged)."""
        self._pending = max(0.0, self._pending - reserved)
        if record is not None:
            self.calls.append(record)
