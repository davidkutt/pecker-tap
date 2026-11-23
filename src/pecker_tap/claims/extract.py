"""Claim extraction: one structured-output call per note section, then the code checks.

The model gets the extraction schema as a forced tool call. Each claim in the reply is validated
on its own (``claims.check``), so one bad claim never costs the rest of its section. Notes marked
``decision: awaiting-david`` yield one ``decision`` claim per section without a model call.

The cost cap is checked before every call. Once it is reached, or the model endpoint refuses the
run's settings (missing key, no credit, no endpoint with zero data retention), the remaining
sections of every note are skipped and listed as not reached.
"""

from __future__ import annotations

import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Literal, cast

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage
from pydantic import BaseModel, ConfigDict

from pecker_tap.claims.check import check_claim
from pecker_tap.claims.prompt import build_messages, prompt_chars
from pecker_tap.claims.schema import Claim, ExtractionResult, RejectedClaim, claim_from_dict
from pecker_tap.cost import (
    CHARS_PER_TOKEN_ESTIMATE,
    CallRecord,
    CostCapReachedError,
    CostMeter,
    tokens_cost,
)
from pecker_tap.llm import EXTRACTION_TOOL
from pecker_tap.notes.loader import Note, Section

StopReason = Literal["cost_cap", "model_setup"]

_FATAL_STATUS = {
    401: "OpenRouter rejected the API key (401)",
    402: "OpenRouter reports insufficient credit (402)",
    403: "OpenRouter refused the request (403)",
    404: (
        "no OpenRouter endpoint satisfies the run's settings: zero data retention, forced tool "
        "calls and provider pins (404)"
    ),
}


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class SectionError(_Strict):
    note_path: str
    section: int
    message: str


class NoteExtraction(_Strict):
    note_path: str
    claims: tuple[dict[str, object], ...] = ()
    """Checked claims as JSON-ready dicts, ``claim_id`` still empty."""
    rejected: tuple[RejectedClaim, ...] = ()
    calls: tuple[CallRecord, ...] = ()
    errors: tuple[SectionError, ...] = ()
    sections_not_reached: tuple[int, ...] = ()
    stop_reason: StopReason | None = None
    """Why sections were not reached: the cost cap or a model setup error."""
    stop_message: str = ""


@dataclass
class RunControl:
    """Shared between the notes of one run: why extraction stopped, if it did."""

    stop_reason: StopReason | None = None
    stop_message: str = ""

    def stop(self, reason: StopReason, message: str) -> None:
        if self.stop_reason is None:
            self.stop_reason, self.stop_message = reason, message


def decision_claims(note: Note) -> list[Claim]:
    """One ``decision`` claim per section of a note that waits for David's decision."""
    claims: list[Claim] = []
    for section in note.sections:
        for number in range(section.first_line, section.last_line + 1):
            line = note.lines[number - 1].strip()
            if line:
                label = section.heading or line
                claims.append(
                    claim_from_dict(
                        {
                            "claim_id": "",
                            "note_path": note.path,
                            "lines": (number, number),
                            "quote": line,
                            "text": f"Awaiting David's decision: {label}",
                            "type": "decision",
                        }
                    )
                )
                break
    return claims


def _usage(reply: AIMessage) -> tuple[int, int, float | None]:
    usage = reply.usage_metadata or {}
    token_usage: object = reply.response_metadata.get("token_usage")
    cost: object = (
        cast("Mapping[str, object]", token_usage).get("cost")
        if isinstance(token_usage, Mapping)
        else None
    )
    reported = float(cost) if isinstance(cost, int | float) else None
    return int(usage.get("input_tokens", 0)), int(usage.get("output_tokens", 0)), reported


def _raw_claims(reply: AIMessage) -> list[object] | None:
    for call in reply.tool_calls:
        if call["name"] == EXTRACTION_TOOL:
            claims: object = call["args"].get("claims", [])
            return cast("list[object]", claims) if isinstance(claims, list) else None
    return None


async def _call(model: BaseChatModel, note: Note, section: Section) -> AIMessage:
    bound = model.bind_tools([ExtractionResult], tool_choice=EXTRACTION_TOOL)
    return await bound.ainvoke(build_messages(note, section))


async def extract_note(
    note: Note,
    *,
    model: BaseChatModel,
    model_name: str,
    meter: CostMeter,
    control: RunControl,
) -> NoteExtraction:
    if note.awaiting_decision:
        claims = [claim.model_dump(mode="json") for claim in decision_claims(note)]
        return NoteExtraction(note_path=note.path, claims=tuple(claims))
    claims: list[dict[str, object]] = []
    rejected: list[RejectedClaim] = []
    calls: list[CallRecord] = []
    errors: list[SectionError] = []
    not_reached: list[int] = []
    for section in note.sections:
        if control.stop_reason is not None:
            not_reached.append(section.index)
            continue
        chars = prompt_chars(build_messages(note, section))
        try:
            reserved = await meter.reserve(chars)
        except CostCapReachedError as exc:
            control.stop("cost_cap", str(exc))
            not_reached.append(section.index)
            continue
        started = time.perf_counter()
        try:
            reply = await _call(model, note, section)
        except Exception as exc:  # one failing call must not end the run
            meter.settle(reserved, None)
            status = getattr(exc, "status_code", None)
            if isinstance(status, int) and status in _FATAL_STATUS:
                control.stop("model_setup", _FATAL_STATUS[status])
                not_reached.append(section.index)
                continue
            where = f" ({status})" if isinstance(status, int) else ""
            errors.append(
                SectionError(
                    note_path=note.path,
                    section=section.index,
                    message=f"model call failed: {type(exc).__name__}{where}",
                )
            )
            continue
        input_tokens, output_tokens, reported = _usage(reply)
        input_tokens = input_tokens or -(-chars // CHARS_PER_TOKEN_ESTIMATE)
        record = CallRecord(
            note_path=note.path,
            section=section.index,
            model=model_name,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=reported
            if reported is not None
            else tokens_cost(meter.price, input_tokens, output_tokens),
            cost_source="reported" if reported is not None else "estimated",
            latency_s=round(time.perf_counter() - started, 4),
        )
        meter.settle(reserved, record)
        calls.append(record)
        raw = _raw_claims(reply)
        if raw is None:
            errors.append(
                SectionError(
                    note_path=note.path,
                    section=section.index,
                    message="the model returned no structured result",
                )
            )
            continue
        for item in raw:
            checked = check_claim(item, note)
            if isinstance(checked, RejectedClaim):
                rejected.append(checked)
            else:
                claims.append(checked.model_dump(mode="json"))
    return NoteExtraction(
        note_path=note.path,
        claims=tuple(claims),
        rejected=tuple(rejected),
        calls=tuple(calls),
        errors=tuple(errors),
        sections_not_reached=tuple(not_reached),
        stop_reason=control.stop_reason if not_reached else None,
        stop_message=control.stop_message if not_reached else "",
    )


def _sort_key(claim: Mapping[str, object], order: Mapping[str, int]) -> tuple[object, ...]:
    lines = cast("Sequence[int]", claim["lines"])
    return (
        order.get(str(claim["note_path"]), len(order)),
        lines[0],
        lines[1],
        str(claim["type"]),
        str(claim["quote"]),
        str(claim["text"]),
    )


def assign_claim_ids(
    extractions: Sequence[NoteExtraction], note_order: Sequence[str]
) -> list[Claim]:
    """Number all kept claims ``c-0001``... in note order, then by line; drop exact repeats."""
    order = {path: index for index, path in enumerate(note_order)}
    unique: dict[str, Mapping[str, object]] = {}
    for extraction in extractions:
        for claim in extraction.claims:
            key = repr(sorted((k, repr(v)) for k, v in claim.items() if k != "claim_id"))
            unique.setdefault(key, claim)
    ordered = sorted(unique.values(), key=lambda claim: _sort_key(claim, order))
    return [
        claim_from_dict({**claim, "claim_id": f"c-{index:04d}"})
        for index, claim in enumerate(ordered, start=1)
    ]
