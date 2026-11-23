"""Run outputs (spec, Inputs and outputs; V1 brief, deliverable 9).

- ``pack.yaml``: one entry per claim (spec schema), then the ``n-NNNN`` new findings.
- ``summary.md``: counts per status, contradictions and new findings with their sources, unclear
  claims by reason, decisions, rejected claims, errors and cost. English in V1.
- ``report.json``: everything, machine-readable, including per-call model usage and cost.
- ``run.json``: the run record (notes SHA, selection, model, settings digest, timings, errors).

Text from notes, the model and sources is escaped and capped before it gets here (pack entries)
or here (rejected quotes, error messages). In ``summary.md`` every such string sits in a code span,
so nothing renders as a link, image or HTML.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field

from pecker_tap.claims.extract import SectionError
from pecker_tap.claims.schema import RejectedClaim
from pecker_tap.cost import CallRecord
from pecker_tap.excerpt import code_span, escape_excerpt
from pecker_tap.notes.loader import NoteParseError
from pecker_tap.verdict.entry import REASONS, STATUSES, PackEntry

RunState = Literal["running", "finished", "interrupted", "cost_cap", "model_setup"]
QUOTE_LIMIT = 200


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RunInfo(_Strict):
    run_id: str
    tool: str
    state: RunState = "running"
    started_at: str
    finished_at: str | None = None
    checked_on: str
    notes_dir: str
    notes_sha: str = "unknown"
    selection: list[str] = Field(default_factory=list[str])
    model: str
    model_origin: str = "--model"
    online: bool = False
    sources: str | None = None
    max_cost_usd: float
    settings_digest: str
    config_digest: str
    atlas_release: str = ""
    atlas_synthetic_pin: bool = False
    exit_code: int | None = None
    duration_s: float | None = None
    errors: list[str] = Field(default_factory=list[str])


class NotReached(_Strict):
    note_path: str
    sections: list[int]


class LookupSummary(_Strict):
    key: str
    sources: list[str]
    failures: list[str]


class RunResult(_Strict):
    notes: int = 0
    entries: list[PackEntry] = Field(default_factory=list[PackEntry])
    rejected: list[RejectedClaim] = Field(default_factory=list[RejectedClaim])
    parse_errors: list[NoteParseError] = Field(default_factory=list[NoteParseError])
    section_errors: list[SectionError] = Field(default_factory=list[SectionError])
    not_reached: list[NotReached] = Field(default_factory=list[NotReached])
    calls: list[CallRecord] = Field(default_factory=list[CallRecord])
    lookups: list[LookupSummary] = Field(default_factory=list[LookupSummary])
    note_warnings: list[str] = Field(default_factory=list[str])
    stop_reason: Literal["cost_cap", "model_setup"] | None = None
    stop_message: str = ""

    @property
    def claim_entries(self) -> list[PackEntry]:
        return [
            e for e in self.entries if not e.claim_id.startswith("n-") and "-n" not in e.claim_id
        ]

    @property
    def cost_usd(self) -> float:
        return round(sum(call.cost_usd for call in self.calls), 6)


def counts(result: RunResult) -> dict[str, object]:
    by_status = Counter(e.status for e in result.entries)
    unclear = Counter(e.reason for e in result.entries if e.status == "unclear" and e.reason)
    claims = len(result.claim_entries)
    return {
        "claims": claims,
        "entries": len(result.entries),
        "by_status": {status: by_status.get(status, 0) for status in STATUSES},
        "unclear_by_reason": {reason: unclear.get(reason, 0) for reason in REASONS},
        "rejected_claims": len(result.rejected),
        "parse_errors": len(result.parse_errors),
        "section_errors": len(result.section_errors),
        "model_calls": len(result.calls),
        "cost_usd": result.cost_usd,
        "cost_per_claim_usd": round(result.cost_usd / claims, 6) if claims else 0.0,
    }


def _rejected_dump(rejected: RejectedClaim) -> dict[str, object]:
    data = rejected.model_dump(mode="json")
    data["quote"] = escape_excerpt(rejected.quote, QUOTE_LIMIT)
    data["type"] = escape_excerpt(rejected.type, 40)
    return data


def report_data(info: RunInfo, result: RunResult) -> dict[str, object]:
    return {
        "run": info.model_dump(mode="json"),
        "counts": counts(result),
        "entries": [e.model_dump(mode="json") for e in result.entries],
        "rejected": [_rejected_dump(r) for r in result.rejected],
        "parse_errors": [e.model_dump(mode="json") for e in result.parse_errors],
        "section_errors": [e.model_dump(mode="json") for e in result.section_errors],
        "not_reached": [n.model_dump(mode="json") for n in result.not_reached],
        "stop_reason": result.stop_reason,
        "stop_message": result.stop_message,
        "calls": [c.model_dump(mode="json") for c in result.calls],
        "lookups": [lookup.model_dump(mode="json") for lookup in result.lookups],
        "note_warnings": result.note_warnings,
    }


def _span(text: str, limit: int = QUOTE_LIMIT) -> str:
    return code_span(escape_excerpt(text, limit))


def _where(entry: PackEntry) -> str:
    first, last = entry.lines
    lines = f"{first}" if first == last else f"{first}-{last}"
    return _span(f"{entry.note_path}:{lines}")


def summary_markdown(info: RunInfo, result: RunResult) -> str:
    numbers = counts(result)
    by_status = Counter(e.status for e in result.entries)
    lines = [
        "# pecker-tap summary",
        "",
        f"- Run: {_span(info.run_id)} ({info.state})",
        f"- Model: {_span(info.model)}",
        f"- Notes: {_span(info.notes_dir)} at {_span(info.notes_sha)}, {result.notes} notes",
        f"- Checked on: {info.checked_on}",
        f"- Evidence: {'online' if info.online else 'offline'}"
        + (f", sources {_span(info.sources)}" if info.sources else ""),
        f"- ATLAS: {_span(info.atlas_release)}"
        + (" (synthetic pin from --sources)" if info.atlas_synthetic_pin else ""),
        f"- Cost: {result.cost_usd:.4f} USD for {len(result.calls)} model calls "
        f"({numbers['cost_per_claim_usd']:.6f} USD per claim; cap {info.max_cost_usd:.2f} USD)",
    ]
    if result.stop_message:
        lines.append(f"- Stopped early: {_span(result.stop_message, 300)}")
    lines += ["", "## Counts", "", "| Status | Entries |", "| --- | ---: |"]
    lines += [f"| {status} | {by_status[status]} |" for status in STATUSES]
    lines += [
        "",
        f"{numbers['claims']} claims, {numbers['rejected_claims']} rejected claims, "
        f"{numbers['parse_errors']} notes that failed to parse, "
        f"{numbers['section_errors']} sections whose model call failed.",
    ]

    def section(title: str, entries: list[PackEntry], show_correct: bool = False) -> None:
        lines.extend(["", f"## {title}", ""])
        if not entries:
            lines.append("None.")
            return
        for entry in entries:
            row = f"- {code_span(entry.claim_id)} {_where(entry)}: {code_span(entry.claim)}"
            if show_correct and entry.correct_value is not None:
                correct = json.dumps(entry.correct_value, ensure_ascii=False, sort_keys=True)
                row += f" Correct: {_span(correct)}."
            if entry.conflict:
                values = "; ".join(f"{c.source_url} {c.value}" for c in entry.conflict)
                row += f" Conflict: {_span(values, 600)}."
            if entry.source_url:
                row += f" Source: {_span(entry.source_url)}."
            lines.append(row)

    section("Contradictions", [e for e in result.entries if e.status == "contradicted"], True)
    section("New findings", [e for e in result.entries if e.status == "new_finding"])

    lines += ["", "## Unclear by reason", ""]
    unclear = [e for e in result.entries if e.status == "unclear" and e.type != "decision"]
    if not unclear:
        lines.append("None.")
    for reason in REASONS:
        group = [e for e in unclear if e.reason == reason]
        if group:
            lines.append(f"- {reason}: {len(group)}")
            lines += [
                f"  - {code_span(e.claim_id)} {_where(e)}: {code_span(e.claim)}" for e in group
            ]

    decisions = [e for e in result.entries if e.type == "decision"]
    lines += ["", "## Decisions", ""]
    lines += [
        f"- {code_span(e.claim_id)} {_where(e)}: {code_span(e.claim)}" for e in decisions
    ] or ["None."]

    lines += ["", "## Rejected claims", ""]
    if not result.rejected:
        lines.append("None.")
    for rejected in result.rejected:
        where = rejected.note_path + (f":{rejected.lines[0]}" if rejected.lines else "")
        lines.append(
            f"- {_span(where)} {rejected.reason}: {_span(rejected.quote)}"
            + (f" ({_span(rejected.detail, 300)})" if rejected.detail else "")
        )

    problems = [
        *(f"{_span(e.path)}: {_span(e.message, 300)}" for e in result.parse_errors),
        *(
            f"{_span(e.note_path)} section {e.section}: {_span(e.message, 300)}"
            for e in result.section_errors
        ),
        *(
            f"{_span(n.note_path)}: sections not reached {', '.join(map(str, n.sections))}"
            for n in result.not_reached
        ),
        *(_span(w, 300) for w in result.note_warnings),
    ]
    lines += ["", "## Errors and notes not reached", ""]
    lines += [f"- {p}" for p in problems] or ["None."]
    return "\n".join(lines) + "\n"


def write_run_record(run_dir: Path, info: RunInfo) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    (run_dir / "run.json").write_text(
        json.dumps(info.model_dump(mode="json"), indent=2) + "\n", encoding="utf-8"
    )


def write_outputs(run_dir: Path, info: RunInfo, result: RunResult) -> None:
    run_dir.mkdir(parents=True, exist_ok=True)
    pack = [e.model_dump(mode="json") for e in result.entries]
    (run_dir / "pack.yaml").write_text(
        yaml.safe_dump(pack, sort_keys=False, allow_unicode=True, width=100), encoding="utf-8"
    )
    (run_dir / "report.json").write_text(
        json.dumps(report_data(info, result), indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    (run_dir / "summary.md").write_text(summary_markdown(info, result), encoding="utf-8")
    write_run_record(run_dir, info)
