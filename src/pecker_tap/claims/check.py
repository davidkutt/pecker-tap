"""Code checks on every extracted claim (spec, Claims; V1 brief, deliverable 3).

The extractor can't invent anything that survives these checks:

- the claim has the extractor schema's shape (unknown fields rejected) and a known ``type``;
- ``lines`` lie inside the note and ``quote`` is an exact substring of those lines;
- every ID in ``entities`` and in the value matches its pattern and appears in the note;
- every URL in ``entities`` and ``cited_urls`` appears in the note verbatim;
- the value validates against the typed value model of the claim's type.

The first failing check names the rejection reason. Rejected claims are listed in the report and
never kept. Error details name fields and rules, never the rejected text itself.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import cast

from pydantic import ValidationError

from pecker_tap.claims.patterns import IdKind, canonical, matches
from pecker_tap.claims.schema import (
    CLAIM_TYPES,
    VALUE_MODELS,
    Claim,
    ExtractedClaim,
    RejectedClaim,
    claim_from_dict,
)
from pecker_tap.notes.loader import Note

ID_KINDS: tuple[IdKind, ...] = ("ghsa", "cve", "atlas", "owasp")


def _field_names(exc: ValidationError) -> str:
    """``field (rule)`` for each error, without the offending input."""
    parts: list[str] = []
    for error in exc.errors(include_input=False, include_url=False):
        where = ".".join(str(part) for part in error["loc"]) or "claim"
        parts.append(f"{where} ({error['type']})")
    return ", ".join(dict.fromkeys(parts))


def _partial(raw: object, note: Note) -> dict[str, object]:
    """Whatever can be shown about a claim that failed the schema check."""
    if not isinstance(raw, Mapping):
        return {"note_path": note.path}
    data = cast("Mapping[str, object]", raw)
    first, last = data.get("first_line"), data.get("last_line")
    lines = (first, last) if isinstance(first, int) and isinstance(last, int) else None
    quote, kind = data.get("quote"), data.get("type")
    return {
        "note_path": note.path,
        "lines": lines,
        "quote": quote if isinstance(quote, str) else "",
        "type": kind if isinstance(kind, str) else "",
    }


def _in_note(note: Note, value: str) -> bool:
    return value.strip().lower() in note.text.lower()


def check_claim(raw: object, note: Note, claim_id: str = "") -> Claim | RejectedClaim:
    """Validate one raw claim from the extractor against ``note``."""
    try:
        extracted = ExtractedClaim.model_validate(raw)
    except ValidationError as exc:
        return RejectedClaim.model_validate(
            {**_partial(raw, note), "reason": "schema", "detail": _field_names(exc)}
        )

    def reject(reason: str, detail: str = "") -> RejectedClaim:
        return RejectedClaim.model_validate(
            {
                "note_path": note.path,
                "lines": (extracted.first_line, extracted.last_line),
                "quote": extracted.quote,
                "type": extracted.type,
                "reason": reason,
                "detail": detail,
            }
        )

    if extracted.type not in CLAIM_TYPES:
        return reject("unknown_type", "type must be one of " + ", ".join(CLAIM_TYPES))
    first, last = extracted.first_line, extracted.last_line
    if not 1 <= first <= last <= len(note.lines):
        return reject("bad_lines", f"lines must lie within 1..{len(note.lines)}, first <= last")
    if not extracted.quote.strip() or extracted.quote not in note.line_span(first, last):
        return reject("quote_not_found", "quote is not an exact substring of the given lines")

    entities: dict[str, list[str]] = {kind: [] for kind in (*ID_KINDS, "urls")}
    for kind in ID_KINDS:
        for item in getattr(extracted.entities, kind):
            if not matches(kind, item):
                return reject("bad_entity_id", f"entities.{kind} has an ID of the wrong form")
            if not _in_note(note, item):
                return reject("entity_not_in_note", f"entities.{kind} names an ID not in the note")
            entities[kind].append(canonical(kind, item))
    for url in [*extracted.entities.urls, *extracted.cited_urls]:
        if not url.strip() or url.strip() not in note.text:
            return reject("url_not_in_note", "a URL is not written in the note")
    entities["urls"] = [url.strip() for url in extracted.entities.urls]

    value_model = VALUE_MODELS[extracted.type]
    value: object = None
    if value_model is not None:
        if extracted.value is None:
            return reject("bad_value", f"a {extracted.type} claim needs a value")
        given = extracted.value.model_dump(exclude_none=True)
        if given.get("no_fix") is False:
            del given["no_fix"]
        relevant = {key: given[key] for key in value_model.model_fields if key in given}
        try:
            typed = value_model.model_validate(relevant)
        except ValidationError as exc:
            return reject("bad_value", _field_names(exc))
        value = typed.model_dump()
        for kind, item in _value_ids(extracted.type, typed.model_dump()):
            if not _in_note(note, item):
                return reject("entity_not_in_note", "the value names an ID not in the note")
            if item not in entities[kind]:
                entities[kind].append(item)

    return claim_from_dict(
        {
            "claim_id": claim_id,
            "note_path": note.path,
            "lines": (first, last),
            "quote": extracted.quote,
            "text": extracted.text.strip() or extracted.quote.strip(),
            "type": extracted.type,
            "entities": {kind: tuple(dict.fromkeys(items)) for kind, items in entities.items()},
            "cited_urls": tuple(dict.fromkeys(url.strip() for url in extracted.cited_urls)),
            "value": value,
        }
    )


def _value_ids(claim_type: str, value: Mapping[str, object]) -> list[tuple[IdKind, str]]:
    ids: list[tuple[IdKind, str]] = []
    if claim_type == "identifier":
        for item in [value.get("id"), *cast("tuple[object, ...]", value.get("aliases") or ())]:
            if isinstance(item, str):
                ids.append(("cve" if item.startswith("CVE-") else "ghsa", item))
    elif claim_type == "taxonomy":
        item, framework = value.get("id"), value.get("framework")
        if isinstance(item, str) and framework in ("atlas", "owasp"):
            ids.append((cast("IdKind", framework), item))
    return ids
