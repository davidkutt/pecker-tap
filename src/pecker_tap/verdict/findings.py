"""Official facts a note lacks (spec, status rule 6b).

For every advisory a note names (its frontmatter and its text, IDs of one advisory grouped), one
``n-NNNN`` entry lists each material field the official record has and the note doesn't state:
severity and score, fixed version or "no fix", CWE, and the CVE/GHSA alias. Dates are not
reported this way.

A field counts as stated when the note has a kept claim of that type for the advisory, or when the
official value itself is written in the note (a score, a fixed version, a CWE ID, an alias ID), so
a claim the extractor missed doesn't turn into a false finding. Values come from the first source
that has them, in the order GitHub global advisory, GitHub repository advisory, CVE.org, NVD.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Sequence
from typing import cast

from pecker_tap.claims.patterns import find_ids
from pecker_tap.claims.schema import (
    Claim,
    SeverityClaim,
    VersionClaim,
    WeaknessClaim,
)
from pecker_tap.evidence.records import AdvisoryRecord, Lookup
from pecker_tap.excerpt import CLAIM_LIMIT, escape_excerpt
from pecker_tap.notes.loader import Note
from pecker_tap.verdict.compare import SOURCE_NAMES, cvss_for, linked, records_for, resolve_ids
from pecker_tap.verdict.entry import PackEntry


def named_advisories(note: Note, claims: Sequence[Claim]) -> list[str]:
    """CVE and GHSA IDs the note names, in order of first appearance in the file."""
    positions: dict[str, int] = {}
    lowered = note.text.lower()
    candidates = [*find_ids("ghsa", note.text), *find_ids("cve", note.text)]
    for claim in claims:
        candidates += [*claim.entities.ghsa, *claim.entities.cve]
    for item in candidates:
        positions.setdefault(item, lowered.find(item.lower()))
    return sorted(positions, key=lambda item: (positions[item] < 0, positions[item], item))


def _line_of(note: Note, ids: Sequence[str]) -> int:
    for number, line in enumerate(note.lines, start=1):
        if any(item.lower() in line.lower() for item in ids):
            return number
    return 1


def _first[T](
    records: Sequence[AdvisoryRecord], pick: Callable[[AdvisoryRecord], T | None]
) -> tuple[AdvisoryRecord | None, T | None]:
    for record in records:
        found = pick(record)
        if found:
            return record, found
    return None, None


def _official(
    records: Sequence[AdvisoryRecord], group: Sequence[str]
) -> dict[str, tuple[object, str, str]]:
    """Field -> (value, how it is written, source URL) for the advisory's material fields."""
    facts: dict[str, tuple[object, str, str]] = {}
    record, label = _first(records, lambda r: r.severity_label)
    cvss_record, cvss = _first(records, lambda r: cvss_for(r, None)[:1])
    if label or cvss:
        value: dict[str, object] = {}
        shown: list[str] = []
        if label:
            value["label"] = label
            shown.append(str(label))
        if cvss:
            entry = cvss[0]
            value |= {"cvss_version": entry.version, "score": entry.score}
            shown.append(f"CVSS {entry.version} {entry.score:g}" if entry.score is not None else "")
        source = record or cvss_record
        if source is not None:
            facts["severity"] = (value, " / ".join(s for s in shown if s), source.url)
    record, packages = _first(records, lambda r: [p for p in r.packages if p.patched_stated])
    if record is not None and packages:
        fixes = list(dict.fromkeys(v for p in packages for v in p.patched))
        facts["fixed"] = (
            fixes[0] if len(fixes) == 1 else fixes or "no fix",
            ", ".join(fixes) or "no fix",
            record.url,
        )
    record, cwes = _first(records, lambda r: list(r.cwes))
    if record is not None and cwes:
        facts["cwe"] = (cwes, ", ".join(cwes), record.url)
    aliases = sorted({i for r in records for i in (*r.ids, *r.aliases)} - set(group))
    if aliases:
        source = next(r.url for r in records if set(aliases) & {*r.ids, *r.aliases})
        facts["alias"] = (aliases, ", ".join(aliases), source)
    return facts


def _stated(
    field: str,
    facts: tuple[object, str, str],
    note: Note,
    claims: Sequence[Claim],
) -> bool:
    value, shown, _ = facts
    text = note.text
    if field == "severity":
        if any(isinstance(c, SeverityClaim) for c in claims):
            return True
        score = cast("dict[str, object]", value).get("score") if isinstance(value, dict) else None
        return isinstance(score, float) and f"{score:g}" in text
    if field == "fixed":
        if any(isinstance(c, VersionClaim) and (c.value.fixed or c.value.no_fix) for c in claims):
            return True
        return shown != "no fix" and all(v.strip() in text for v in shown.split(","))
    if field == "cwe":
        return any(isinstance(c, WeaknessClaim) for c in claims) or any(
            cwe.lower() in text.lower() for cwe in shown.split(", ")
        )
    if field == "alias":
        return all(item.lower() in text.lower() for item in shown.split(", "))
    return False


def _claim_urls(claim: Claim, note: Note, lookups: Mapping[str, Lookup]) -> set[str]:
    ids = resolve_ids(claim, note, lookups)
    if not isinstance(ids, list):
        return set()
    return {r.url for r in records_for(ids, lookups)[0]}


def missing_facts(
    note: Note,
    claims: Sequence[Claim],
    lookups: Mapping[str, Lookup],
    checked_on: str,
    start: int,
) -> list[PackEntry]:
    """``n-NNNN`` entries for one note, numbered from ``start``."""
    entries: list[PackEntry] = []
    groups = linked(named_advisories(note, claims), lookups)
    for group in groups:
        records, _ = records_for(group, lookups)
        records = [r for r in records if not r.withdrawn]
        if not records:
            continue
        urls = {r.url for r in records}
        about = [c for c in claims if _claim_urls(c, note, lookups) & urls]
        facts = _official(records, group)
        missing = {
            field: fact for field, fact in facts.items() if not _stated(field, fact, note, about)
        }
        if not missing:
            continue
        name = group[0]
        listing = "; ".join(f"{field}: {shown}" for field, (_, shown, _) in missing.items())
        sources = "; ".join(
            f"{field} from {SOURCE_NAMES[next(r.source for r in records if r.url == url)]}"
            for field, (_, _, url) in missing.items()
        )
        entries.append(
            PackEntry(
                claim_id=f"n-{start + len(entries):04d}",
                status="new_finding",
                note_path=note.path,
                lines=(line := _line_of(note, group), line),
                claim=escape_excerpt(
                    f"Official facts for {name} that the note doesn't state: {listing}.",
                    CLAIM_LIMIT,
                ),
                type="advisory",
                source_url=records[0].url,
                evidence=escape_excerpt(listing),
                note=escape_excerpt(f"Values taken {sources}.", CLAIM_LIMIT),
                correct_value={field: value for field, (value, _, _) in missing.items()},
                checked_on=checked_on,
            )
        )
    return entries
