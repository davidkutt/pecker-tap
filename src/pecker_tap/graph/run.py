"""The run graph (spec, Graph; V1 brief, deliverable 8).

``load_notes -> extract (Send per note) -> number_claims -> api_lookup (Send per GHSA and ATLAS
ID) -> lookup_cve (Send per CVE ID) -> compare (Send per claim) -> collect -> write_pack``

Lookups fan out per identifier rather than per claim: claims that name the same advisory share
one lookup, which keeps the API rate limits. CVE lookups run after the GHSA lookups so a CVE that
a GHSA record already lists as an alias needs no second GitHub search. Every claim is then compared
by code in its own ``compare`` task.

A SQLite checkpointer in the run folder saves every step: an interrupted run continues with
``--resume <run_id>`` and finished tasks are not repeated. Runtime objects (the model, the HTTP
client, the cost meter) live outside the state; the state holds only JSON-ready data.
"""

from __future__ import annotations

import operator
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Annotated, Any, TypedDict, cast

from langchain_core.language_models import BaseChatModel
from langgraph.checkpoint.sqlite.aio import AsyncSqliteSaver
from langgraph.constants import END, START
from langgraph.graph.state import StateGraph  # pyright: ignore[reportMissingTypeStubs]
from langgraph.types import Send

from pecker_tap.claims.extract import NoteExtraction, RunControl, assign_claim_ids, extract_note
from pecker_tap.claims.patterns import find_ids
from pecker_tap.claims.schema import Claim, TaxonomyClaim, advisory_ids, claim_from_dict
from pecker_tap.cost import CallRecord, CostMeter
from pecker_tap.evidence.advisories import lookup_advisory, repo_hints
from pecker_tap.evidence.atlas import AtlasSource
from pecker_tap.evidence.http import HttpClient
from pecker_tap.evidence.records import Lookup
from pecker_tap.notes.loader import Note, NoteParseError, load_notes
from pecker_tap.pack.writers import LookupSummary, NotReached, RunInfo, RunResult, write_outputs
from pecker_tap.verdict.compare import SOURCE_NAMES, ClaimContext, compare_claim
from pecker_tap.verdict.entry import PackEntry
from pecker_tap.verdict.findings import missing_facts, named_advisories

CHECKPOINT_FILE = "checkpoint.sqlite"


def _merge(left: dict[str, Any] | None, right: dict[str, Any] | None) -> dict[str, Any]:
    return {**(left or {}), **(right or {})}


class RunState(TypedDict, total=False):
    notes: list[dict[str, Any]]
    parse_errors: list[dict[str, Any]]
    extractions: Annotated[list[dict[str, Any]], operator.add]
    claims: list[dict[str, Any]]
    lookups: Annotated[dict[str, Any], _merge]
    entries: Annotated[list[dict[str, Any]], operator.add]
    result: dict[str, Any]


@dataclass
class RunDeps:
    """Runtime objects for one run (not checkpointed)."""

    notes_dir: Path
    patterns: Sequence[str]
    model: BaseChatModel
    model_name: str
    http: HttpClient
    atlas: AtlasSource
    meter: CostMeter
    run_dir: Path
    info: RunInfo
    control: RunControl = field(default_factory=RunControl)


def _notes(state: RunState) -> list[Note]:
    return [Note.model_validate(raw) for raw in state.get("notes", [])]


def _note_map(state: RunState) -> dict[str, Note]:
    return {note.path: note for note in _notes(state)}


def _claims(state: RunState) -> list[Claim]:
    return [claim_from_dict(raw) for raw in state.get("claims", [])]


def _lookups(raw: Mapping[str, Any]) -> dict[str, Lookup]:
    return {key: Lookup.model_validate(value) for key, value in raw.items()}


def note_ids(note: Note, claims: Sequence[Claim]) -> list[str]:
    """Every advisory ID a note names: frontmatter, text and claim entities."""
    named = named_advisories(note, claims)
    for item in [*note.frontmatter.ghsa, *note.frontmatter.cve]:
        named += [*find_ids("ghsa", item), *find_ids("cve", item)]
    return list(dict.fromkeys(named))


def lookup_keys(notes: Sequence[Note], claims: Sequence[Claim]) -> tuple[
    dict[str, list[str]], list[str], list[str]
]:  # fmt: skip
    """GHSA keys with their repository hints, CVE keys, and ATLAS keys."""
    by_note: dict[str, list[Claim]] = {}
    for claim in claims:
        by_note.setdefault(claim.note_path, []).append(claim)
    ids: list[str] = []
    for note in notes:
        ids += note_ids(note, by_note.get(note.path, []))
    for claim in claims:
        ids += advisory_ids(claim)
    ghsa: dict[str, list[str]] = {}
    cves: list[str] = []
    for item in dict.fromkeys(ids):
        if item.startswith("GHSA-"):
            ghsa[item] = list(
                dict.fromkeys(h for note in notes for h in repo_hints(note.text, item))
            )
        else:
            cves.append(item)
    atlas = [
        claim.value.id
        for claim in claims
        if isinstance(claim, TaxonomyClaim) and claim.value.framework == "atlas"
    ]
    return ghsa, cves, list(dict.fromkeys(atlas))


def build_graph(deps: RunDeps) -> Any:
    """The uncompiled graph (typed ``Any``: LangGraph's generics leak unknown types)."""
    graph: Any = StateGraph(RunState)

    async def load(state: RunState) -> dict[str, Any]:
        loaded = load_notes(deps.notes_dir, deps.patterns)
        return {
            "notes": [note.model_dump(mode="json") for note in loaded.notes],
            "parse_errors": [error.model_dump(mode="json") for error in loaded.errors],
        }

    def route_extract(state: RunState) -> list[Send] | str:
        notes = state.get("notes", [])
        return [Send("extract", {"note": note}) for note in notes] or "number_claims"

    async def extract(payload: dict[str, Any]) -> dict[str, Any]:
        note = Note.model_validate(payload["note"])
        result = await extract_note(
            note,
            model=deps.model,
            model_name=deps.model_name,
            meter=deps.meter,
            control=deps.control,
        )
        return {"extractions": [result.model_dump(mode="json")]}

    async def number_claims(state: RunState) -> dict[str, Any]:
        extractions = [NoteExtraction.model_validate(e) for e in state.get("extractions", [])]
        order = [note.path for note in _notes(state)]
        claims = assign_claim_ids(extractions, order)
        return {"claims": [claim.model_dump(mode="json") for claim in claims]}

    def route_lookups(state: RunState) -> list[Send] | str:
        ghsa, _, atlas = lookup_keys(_notes(state), _claims(state))
        sends = [Send("api_lookup", {"key": key, "hints": hints}) for key, hints in ghsa.items()]
        sends += [Send("api_lookup", {"key": key, "hints": []}) for key in atlas]
        return sends or "plan_cve"

    async def api_lookup(payload: dict[str, Any]) -> dict[str, Any]:
        key: str = payload["key"]
        if key.startswith("AML."):
            lookup = await deps.atlas.lookup(key)
        else:
            lookup = await lookup_advisory(key, payload["hints"], deps.http)
        return {"lookups": {key: lookup.model_dump(mode="json")}}

    async def plan_cve(state: RunState) -> dict[str, Any]:
        return {}

    def route_cve(state: RunState) -> list[Send] | str:
        _, cves, _ = lookup_keys(_notes(state), _claims(state))
        known = {k: v for k, v in state.get("lookups", {}).items() if k.startswith("GHSA-")}
        todo = [key for key in cves if key not in state.get("lookups", {})]
        return [Send("lookup_cve", {"key": key, "known": known}) for key in todo] or "plan_compare"

    async def lookup_cve(payload: dict[str, Any]) -> dict[str, Any]:
        known = list(_lookups(payload["known"]).values())
        lookup = await lookup_advisory(payload["key"], [], deps.http, known=known)
        return {"lookups": {payload["key"]: lookup.model_dump(mode="json")}}

    async def plan_compare(state: RunState) -> dict[str, Any]:
        return {}

    def route_compare(state: RunState) -> list[Send] | str:
        notes = _note_map(state)
        lookups = state.get("lookups", {})
        sends: list[Send] = []
        for claim in _claims(state):
            note = notes[claim.note_path]
            wanted = {*advisory_ids(claim), *note_ids(note, [claim])}
            if isinstance(claim, TaxonomyClaim):
                wanted.add(claim.value.id)
            relevant = _related(wanted, lookups)
            sends.append(
                Send(
                    "compare",
                    {
                        "claim": claim.model_dump(mode="json"),
                        "note": note.model_dump(mode="json"),
                        "lookups": relevant,
                    },
                )
            )
        return sends or "collect"

    async def compare(payload: dict[str, Any]) -> dict[str, Any]:
        claim = claim_from_dict(payload["claim"])
        context = ClaimContext(
            note=Note.model_validate(payload["note"]),
            lookups=_lookups(payload["lookups"]),
            checked_on=deps.info.checked_on,
        )
        return {"entries": [e.model_dump(mode="json") for e in compare_claim(claim, context)]}

    async def collect(state: RunState) -> dict[str, Any]:
        return {"result": collect_result(state, deps).model_dump(mode="json")}

    async def write_pack(state: RunState) -> dict[str, Any]:
        # The CLI writes the outputs again with the final run record (state, exit code, timing).
        write_outputs(deps.run_dir, deps.info, RunResult.model_validate(state.get("result", {})))
        return {}

    graph.add_node("load_notes", load)
    graph.add_node("extract", extract)
    graph.add_node("number_claims", number_claims)
    graph.add_node("api_lookup", api_lookup)
    graph.add_node("plan_cve", plan_cve)
    graph.add_node("lookup_cve", lookup_cve)
    graph.add_node("plan_compare", plan_compare)
    graph.add_node("compare", compare)
    graph.add_node("collect", collect)
    graph.add_node("write_pack", write_pack)
    graph.add_edge(START, "load_notes")
    graph.add_conditional_edges("load_notes", route_extract, ["extract", "number_claims"])
    graph.add_edge("extract", "number_claims")
    graph.add_conditional_edges("number_claims", route_lookups, ["api_lookup", "plan_cve"])
    graph.add_edge("api_lookup", "plan_cve")
    graph.add_conditional_edges("plan_cve", route_cve, ["lookup_cve", "plan_compare"])
    graph.add_edge("lookup_cve", "plan_compare")
    graph.add_conditional_edges("plan_compare", route_compare, ["compare", "collect"])
    graph.add_edge("compare", "collect")
    graph.add_edge("collect", "write_pack")
    graph.add_edge("write_pack", END)
    return graph


def _related(wanted: set[str], lookups: Mapping[str, Any]) -> dict[str, Any]:
    """The lookups for ``wanted`` plus every lookup of an ID their records name."""
    keys = set(wanted)
    for key in list(wanted):
        raw = lookups.get(key)
        if raw is None:
            continue
        for record in Lookup.model_validate(raw).records:
            keys |= {*record.ids, *record.aliases}
    return {key: lookups[key] for key in sorted(keys) if key in lookups}


def collect_result(state: RunState, deps: RunDeps) -> RunResult:
    notes = _notes(state)
    claims = _claims(state)
    lookups = _lookups(state.get("lookups", {}))
    extractions = [NoteExtraction.model_validate(e) for e in state.get("extractions", [])]
    order = {note.path: index for index, note in enumerate(notes)}
    extractions.sort(key=lambda e: order.get(e.note_path, len(order)))
    entries = [PackEntry.model_validate(e) for e in state.get("entries", [])]
    entries.sort(key=lambda e: e.claim_id)
    by_note: dict[str, list[Claim]] = {}
    for claim in claims:
        by_note.setdefault(claim.note_path, []).append(claim)
    findings: list[PackEntry] = []
    for note in notes:
        findings += missing_facts(
            note, by_note.get(note.path, []), lookups, deps.info.checked_on, start=len(findings) + 1
        )
    summaries = [
        LookupSummary(
            key=key,
            sources=[f"{SOURCE_NAMES.get(r.source, r.source)} {r.url}" for r in lookup.records]
            + ([f"ATLAS {lookup.atlas.release} {lookup.atlas.url}"] if lookup.atlas else []),
            failures=[
                f"{f.source} {f.url}: {f.reason} {f.detail}".strip() for f in lookup.failures
            ],
        )
        for key, lookup in sorted(lookups.items())
    ]
    calls: list[CallRecord] = [c for e in extractions for c in e.calls]
    return RunResult(
        notes=len(notes),
        entries=[*entries, *findings],
        rejected=[r for e in extractions for r in e.rejected],
        parse_errors=[NoteParseError.model_validate(p) for p in state.get("parse_errors", [])],
        section_errors=[s for e in extractions for s in e.errors],
        not_reached=[
            NotReached(note_path=e.note_path, sections=list(e.sections_not_reached))
            for e in extractions
            if e.sections_not_reached
        ],
        calls=calls,
        lookups=summaries,
        note_warnings=[f"{note.path}: {w}" for note in notes for w in note.warnings],
        stop_reason=next((e.stop_reason for e in extractions if e.stop_reason), None),
        stop_message=next((e.stop_message for e in extractions if e.stop_message), ""),
    )


@dataclass(frozen=True)
class GraphOutcome:
    result: RunResult | None
    resumed: bool
    already_finished: bool


async def earlier_calls(run_dir: Path, run_id: str) -> list[CallRecord]:
    """Model calls a stopped run already paid for (from its checkpoint), for the cost meter."""
    db = run_dir / CHECKPOINT_FILE
    if not db.is_file():
        return []
    async with AsyncSqliteSaver.from_conn_string(str(db)) as saver:
        builder: Any = StateGraph(RunState)
        graph: Any = builder.compile(checkpointer=saver)
        snapshot = await graph.aget_state(cast("Any", {"configurable": {"thread_id": run_id}}))
        values = cast("dict[str, Any]", snapshot.values or {})
    return [
        CallRecord.model_validate(call)
        for extraction in values.get("extractions", [])
        for call in extraction.get("calls", [])
    ]


async def run_graph(deps: RunDeps, *, resume: bool, concurrency: int) -> GraphOutcome:
    config: dict[str, Any] = {
        "configurable": {"thread_id": deps.info.run_id},
        "max_concurrency": concurrency,
        "recursion_limit": 50,
    }
    db = deps.run_dir / CHECKPOINT_FILE
    deps.run_dir.mkdir(parents=True, exist_ok=True)
    async with AsyncSqliteSaver.from_conn_string(str(db)) as saver:
        graph: Any = build_graph(deps).compile(checkpointer=saver)
        snapshot = await graph.aget_state(cast("Any", config))
        started = bool(snapshot.values)
        if resume and started and not snapshot.next:
            return GraphOutcome(None, resumed=True, already_finished=True)
        if resume and started:
            final = await graph.ainvoke(None, cast("Any", config), durability="sync")
        else:
            final = await graph.ainvoke({}, cast("Any", config), durability="sync")
    state = cast("dict[str, Any]", final)
    result = RunResult.model_validate(state["result"]) if "result" in state else None
    return GraphOutcome(result, resumed=resume and started, already_finished=False)
