"""The pack entry (spec, Statuses: Pack entry) and date comparison at the note's precision."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict

Status = Literal["verified", "contradicted", "new_finding", "unclear"]
Reason = Literal["unreachable", "secondary_only", "ambiguous", "no_source", "not_checked"]
STATUSES: tuple[Status, ...] = ("verified", "contradicted", "new_finding", "unclear")
REASONS: tuple[Reason, ...] = (
    "unreachable",
    "secondary_only",
    "ambiguous",
    "no_source",
    "not_checked",
)


class ConflictValue(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    source_url: str
    value: str


class PackEntry(BaseModel):
    """One pack entry. Field names shared with Wren's packs keep Wren's names and meaning."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    claim_id: str
    status: Status
    reason: Reason | None = None
    note_path: str
    lines: tuple[int, int]
    claim: str
    type: str
    source_url: str | None = None
    source_field: str | None = None
    evidence: str | None = None
    note: str = ""
    correct_value: dict[str, object] | None = None
    conflict: tuple[ConflictValue, ...] | None = None
    decided_by: Literal["code", "judge"] = "code"
    archived: bool = False
    checked_on: str
    warnings: tuple[str, ...] = ()


def utc_day(timestamp: str) -> str | None:
    """The UTC calendar day (``YYYY-MM-DD``) of an ISO timestamp or date; ``None`` if unreadable."""
    text = timestamp.strip()
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(UTC)
    return parsed.date().isoformat()


def date_matches(note_date: str, source_timestamp: str) -> bool | None:
    """A note date (``YYYY``, ``YYYY-MM`` or ``YYYY-MM-DD``) matches any source day it covers."""
    day = utc_day(source_timestamp)
    if day is None:
        return None
    return day == note_date or day.startswith(note_date + "-")
