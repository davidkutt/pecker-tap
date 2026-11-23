"""Code comparison: a claim against every source value (spec, Statuses; V1 brief, deliverable 7).

For each claim, code collects one observation per source that states the claim's field and
applies the status rules:

1. No observation: ``unclear`` with ``unreachable`` (a source failed) or ``no_source``.
2. Every source accepts the note's value: ``verified``.
3. No source accepts it: ``contradicted``, with the correct value when the sources agree, or every
   source value in ``conflict`` when they don't. The verifier never picks a winner.
4. Some sources accept it and others don't (primaries disagree): ``verified`` with every value in
   ``conflict``. The note "records the conflict" when every other value is written in the claim's
   section; if it doesn't, a separate ``new_finding`` entry ``<claim_id>-n1`` records the conflict
   (spec, status rule 6a).

Severity and identifier claims check each stated part (label, score, vector; existence, product,
aliases) the same way and combine: any part contradicted makes the claim contradicted, all parts
verified make it verified, anything else stays unclear.

Which advisory a claim is about: its own IDs first, else the note's frontmatter IDs if they name
exactly one advisory, else ``unclear`` / ``ambiguous``. A 404 from an advisory API is not
evidence that an ID doesn't exist; only a pinned ATLAS release is complete enough for that.
"""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

from pecker_tap.claims.patterns import advisory_kind, canonical
from pecker_tap.claims.schema import (
    Claim,
    DateClaim,
    IdentifierClaim,
    ProductClaim,
    SeverityClaim,
    TaxonomyClaim,
    VersionClaim,
    WeaknessClaim,
    advisory_ids,
)
from pecker_tap.evidence.records import (
    AdvisoryRecord,
    AffectedPackage,
    Cvss,
    Lookup,
    SourceFailure,
)
from pecker_tap.excerpt import CLAIM_LIMIT, escape_excerpt
from pecker_tap.notes.loader import Note
from pecker_tap.verdict.entry import ConflictValue, PackEntry, Reason, Status, date_matches, utc_day
from pecker_tap.verdict.versions import same_range, same_version

SOURCE_NAMES = {
    "github_global": "GitHub global advisory",
    "github_repo": "GitHub repository advisory",
    "cve_org": "CVE.org",
    "nvd": "NVD",
    "atlas": "ATLAS",
}
SOURCE_ORDER = ("github_global", "github_repo", "cve_org", "nvd")
_NAME_CHARS = re.compile(r"[^a-z0-9]")


@dataclass(frozen=True, slots=True)
class Obs:
    source: str
    url: str
    field: str
    display: str
    accepts: bool
    value: object
    exact: bool = True
    mention: str | None = None
    """How the value would be written in a note that records it (default: ``display``)."""


@dataclass
class Decision:
    status: Status
    reason: Reason | None = None
    note: str = ""
    source_url: str | None = None
    source_field: str | None = None
    evidence: str | None = None
    correct_value: dict[str, object] | None = None
    conflict: list[ConflictValue] | None = None
    unrecorded_conflict: bool = False
    warnings: list[str] = field(default_factory=list[str])


@dataclass(frozen=True)
class ClaimContext:
    note: Note
    lookups: Mapping[str, Lookup]
    checked_on: str


# --- helpers -----------------------------------------------------------------------------------


def norm_name(value: str) -> str:
    return _NAME_CHARS.sub("", value.lower())


def names_match(a: str, b: str) -> bool:
    left, right = norm_name(a), norm_name(b)
    if not left or not right:
        return False
    if left == right:
        return True
    shorter = min(left, right, key=len)
    return len(shorter) >= 4 and (left in right or right in left)


def _sources(obs: Sequence[Obs]) -> str:
    names = list(dict.fromkeys(SOURCE_NAMES.get(o.source, o.source) for o in obs))
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " and " + names[-1]


def section_text(note: Note, line: int) -> str:
    for section in note.sections:
        if section.first_line <= line <= section.last_line:
            return note.line_span(section.first_line, section.last_line)
    return note.line_span(line, line)


def _failures_reason(failures: Sequence[SourceFailure]) -> Reason:
    bad = {"unreachable", "blocked", "bad_data"}
    return "unreachable" if any(f.reason in bad for f in failures) else "no_source"


def _failures_note(failures: Sequence[SourceFailure]) -> str:
    if not failures:
        return "No primary source was found."
    parts = [
        f"{SOURCE_NAMES.get(f.source, f.source)}: {f.reason.replace('_', ' ')}"
        + (f" ({f.detail})" if f.detail else "")
        for f in failures
    ]
    return "No primary source could be read. " + "; ".join(parts) + "."


def judge(label: str, obs: Sequence[Obs], note_value: str, text: str, key: str) -> Decision:
    """Apply the status rules to the observations of one field."""
    if not obs:
        return Decision("unclear", "no_source", note=f"No primary source states the {label}.")
    warnings = (
        [f"{label}: compared as plain strings (no version parser for this ecosystem)"]
        if any(not o.exact for o in obs)
        else []
    )
    distinct: dict[str, Obs] = {}
    for o in obs:
        distinct.setdefault(o.display, o)
    accepted = [o for o in obs if o.accepts]
    first = accepted[0] if accepted else obs[0]
    base = Decision(
        "verified",
        source_url=first.url,
        source_field=first.field,
        evidence=escape_excerpt(f"{first.field}: {first.display}"),
        warnings=warnings,
    )
    if len(accepted) == len(obs):
        base.note = f"The {label} is {first.display} in {_sources(obs)}."
        return base
    conflict = list(
        {(o.url, o.display): ConflictValue(source_url=o.url, value=o.display) for o in obs}.values()
    )
    if not accepted:
        base.status = "contradicted"
        if len(distinct) == 1:
            base.correct_value = {key: first.value}
            base.note = (
                f"The note says {note_value}; the {label} is {first.display} in {_sources(obs)}."
            )
        else:
            base.conflict = conflict
            values = "; ".join(f"{_sources([o])}: {o.display}" for o in distinct.values())
            base.note = (
                f"The note says {note_value}; the primary sources disagree and none states it "
                f"({values})."
            )
        return base
    others = [o.display for o in distinct.values() if not o.accepts]
    mentions = [o.mention or o.display for o in distinct.values() if not o.accepts]
    recorded = all(
        part.strip() in text for value in mentions for part in value.split(",") if part.strip()
    )
    base.conflict = conflict
    base.unrecorded_conflict = not recorded
    base.note = (
        f"The {label} is {first.display} in {_sources(accepted)} but {', '.join(others)} in "
        f"{_sources([o for o in obs if not o.accepts])}. "
        + ("The note records the conflict." if recorded else "The note doesn't record it.")
    )
    return base


def merge(parts: Sequence[Decision]) -> Decision:
    if len(parts) == 1:
        return parts[0]
    contradicted = [p for p in parts if p.status == "contradicted"]
    unclear = [p for p in parts if p.status == "unclear"]
    chosen = contradicted or unclear or list(parts)
    lead = chosen[0]
    correct: dict[str, object] = {}
    for part in contradicted:
        correct.update(part.correct_value or {})
    conflicts = [c for p in parts for c in (p.conflict or [])]
    status: Status = "contradicted" if contradicted else "unclear" if unclear else "verified"
    return Decision(
        status,
        reason=lead.reason if status == "unclear" else None,
        note=" ".join(p.note for p in parts),
        source_url=lead.source_url,
        source_field=lead.source_field,
        evidence=lead.evidence,
        correct_value=correct or None,
        conflict=list(dict.fromkeys(conflicts)) or None,
        unrecorded_conflict=any(p.unrecorded_conflict for p in parts),
        warnings=[w for p in parts for w in p.warnings],
    )


# --- which advisory ----------------------------------------------------------------------------


def linked(ids: Sequence[str], lookups: Mapping[str, Lookup]) -> list[list[str]]:
    """Group IDs that name the same advisory (one lists the other among its IDs or aliases)."""
    groups: list[list[str]] = []
    for item in ids:
        names = {item}
        lookup = lookups.get(item)
        if lookup is not None:
            for record in lookup.records:
                names |= {*record.ids, *record.aliases}
        home = next(
            (
                g
                for g in groups
                if names & set(g)
                or any(
                    item in {*r.ids, *r.aliases}
                    for other in g
                    for r in (lookups[other].records if other in lookups else ())
                )
            ),
            None,
        )
        if home is None:
            groups.append([item])
        elif item not in home:
            home.append(item)
    return groups


def resolve_ids(claim: Claim, note: Note, lookups: Mapping[str, Lookup]) -> list[str] | Reason:
    ids = advisory_ids(claim)
    if ids:
        return ids
    named = [*note.frontmatter.ghsa, *note.frontmatter.cve]
    canonical_ids = [
        canonical(kind, item) for item in named if (kind := advisory_kind(item)) is not None
    ]
    groups = linked(list(dict.fromkeys(canonical_ids)), lookups)
    if not groups:
        return "no_source"
    if len(groups) > 1:
        return "ambiguous"
    return groups[0]


def records_for(
    ids: Sequence[str], lookups: Mapping[str, Lookup]
) -> tuple[list[AdvisoryRecord], list[SourceFailure]]:
    records: dict[str, AdvisoryRecord] = {}
    failures: dict[tuple[str, str], SourceFailure] = {}
    for item in ids:
        lookup = lookups.get(item)
        if lookup is None:
            continue
        for record in lookup.records:
            records.setdefault(record.url, record)
        for failure in lookup.failures:
            failures.setdefault((failure.source, failure.url), failure)
    ordered = sorted(records.values(), key=lambda r: SOURCE_ORDER.index(r.source))
    return ordered, list(failures.values())


# --- observations per type ---------------------------------------------------------------------


def _packages(record: AdvisoryRecord, package: str | None) -> list[AffectedPackage]:
    if package is None:
        return list(record.packages)
    return [p for p in record.packages if names_match(p.name, package)]


def version_decision(claim: VersionClaim, records: Sequence[AdvisoryRecord], text: str) -> Decision:
    value = claim.value
    if value.package is None:
        for record in records:
            fixes = {p.patched for p in record.packages if p.patched_stated}
            if len(fixes) > 1:
                return Decision(
                    "unclear",
                    "ambiguous",
                    note=f"{SOURCE_NAMES[record.source]} lists several packages with different "
                    "fixes and the claim doesn't name the package.",
                )
    obs: list[Obs] = []
    for record in records:
        packages = _packages(record, value.package)
        if value.affected is not None:
            ranges = [
                (p, r.strip())
                for p in packages
                for r in (p.vulnerable_range or "").split(";")
                if r.strip()
            ]
            if not ranges:
                continue
            results = [same_range(value.affected, r, p.ecosystem) for p, r in ranges]
            display = "; ".join(dict.fromkeys(r for _, r in ranges))
            obs.append(
                Obs(
                    record.source,
                    record.url,
                    ranges[0][0].field.rsplit(".", 1)[0] + ".vulnerable_version_range"
                    if record.source.startswith("github")
                    else ranges[0][0].field,
                    display,
                    any(equal for equal, _ in results),
                    ranges[0][1] if len(ranges) == 1 else display,
                    all(exact for _, exact in results),
                )
            )
            continue
        stated = [p for p in packages if p.patched_stated]
        if not stated:
            continue
        fixes = list(dict.fromkeys(v for p in stated for v in p.patched))
        display = ", ".join(fixes) if fixes else "no fix"
        eco = stated[0].ecosystem or next(
            (p.ecosystem for r in records for p in r.packages if p.ecosystem), None
        )
        if value.no_fix:
            accepts, exact = not fixes, True
        else:
            results = [same_version(value.fixed or "", f, eco) for f in fixes]
            accepts = any(equal for equal, _ in results)
            exact = all(e for _, e in results) if results else True
        obs.append(
            Obs(
                record.source,
                record.url,
                stated[0].field,
                display,
                accepts,
                fixes[0] if len(fixes) == 1 else (fixes or None),
                exact,
            )
        )
    if value.affected is not None:
        return judge("affected range", obs, value.affected, text, "affected")
    note_value = "there is no fix" if value.no_fix else f"fixed in {value.fixed}"
    return judge("fixed version", obs, note_value, text, "fixed")


def cvss_for(record: AdvisoryRecord, version: str | None) -> list[Cvss]:
    if version is not None:
        return [c for c in record.cvss if c.version == version]
    for wanted in (("3.1", "3.0"), ("4.0",), ("2.0",)):
        found = [c for c in record.cvss if c.version in wanted]
        if found:
            return found
    return []


def _vector_body(vector: str) -> str:
    text = vector.strip().upper().replace(" ", "")
    return text.split("/", 1)[1] if text.startswith("CVSS:") and "/" in text else text


def severity_decision(
    claim: SeverityClaim, records: Sequence[AdvisoryRecord], text: str
) -> Decision:
    value = claim.value
    parts: list[Decision] = []
    if value.label is not None:
        obs: list[Obs] = []
        for record in records:
            if record.source.startswith("github") and record.severity_label:
                obs.append(
                    Obs(
                        record.source,
                        record.url,
                        record.severity_field or "severity",
                        record.severity_label,
                        record.severity_label == value.label,
                        record.severity_label,
                    )
                )
            elif not record.source.startswith("github"):
                for cvss in cvss_for(record, value.cvss_version)[:1]:
                    if cvss.label:
                        obs.append(
                            Obs(
                                record.source,
                                record.url,
                                f"{cvss.field}.baseSeverity",
                                cvss.label,
                                cvss.label == value.label,
                                cvss.label,
                            )
                        )
        parts.append(judge("severity label", obs, value.label, text, "label"))
    if value.score is not None:
        obs = []
        for record in records:
            for cvss in cvss_for(record, value.cvss_version):
                if cvss.score is not None:
                    shown = f"CVSS {cvss.version} {cvss.score:g}"
                    obs.append(
                        Obs(
                            record.source,
                            record.url,
                            cvss.field,
                            shown,
                            round(cvss.score, 1) == round(value.score, 1),
                            cvss.score,
                            mention=f"{cvss.score:g}",
                        )
                    )
        version = f"CVSS {value.cvss_version} " if value.cvss_version else ""
        parts.append(judge("CVSS score", obs, f"{version}{value.score:g}", text, "score"))
    if value.vector:
        wanted = _vector_body(value.vector)
        prefix = value.vector.strip().upper()
        version = prefix[5:8] if prefix.startswith("CVSS:") else value.cvss_version
        obs = []
        for record in records:
            for cvss in cvss_for(record, version):
                if cvss.vector:
                    obs.append(
                        Obs(
                            record.source,
                            record.url,
                            cvss.field,
                            cvss.vector,
                            _vector_body(cvss.vector) == wanted,
                            cvss.vector,
                        )
                    )
        parts.append(judge("CVSS vector", obs, value.vector, text, "vector"))
    return merge(parts)


def weakness_decision(
    claim: WeaknessClaim, records: Sequence[AdvisoryRecord], text: str
) -> Decision:
    wanted = set(claim.value.cwe)
    obs = [
        Obs(
            r.source,
            r.url,
            r.cwe_field or "cwes",
            ", ".join(r.cwes),
            wanted <= set(r.cwes),
            list(r.cwes),
        )
        for r in records
        if r.cwes
    ]
    return judge("weakness", obs, ", ".join(claim.value.cwe), text, "cwe")


def date_decision(claim: DateClaim, records: Sequence[AdvisoryRecord], text: str) -> Decision:
    kind = claim.value.kind
    ghsa_named = bool(claim.entities.ghsa) or any(
        i.startswith("GHSA-") for i in advisory_ids(claim)
    )
    cve_named = bool(claim.entities.cve) or any(i.startswith("CVE-") for i in advisory_ids(claim))
    allowed: set[str] = set()
    if ghsa_named:
        allowed |= {"github_global", "github_repo"}
    if cve_named or not ghsa_named:
        allowed |= {"cve_org", "nvd"}
    obs: list[Obs] = []
    for record in records:
        if record.source not in allowed:
            continue
        stamp = record.published if kind == "published" else record.updated
        field_name = record.published_field if kind == "published" else record.updated_field
        day = utc_day(stamp) if stamp else None
        if stamp and day:
            obs.append(
                Obs(
                    record.source,
                    record.url,
                    field_name or kind,
                    day,
                    bool(date_matches(claim.value.date, stamp)),
                    day,
                )
            )
    return judge(f"{kind} date", obs, claim.value.date, text, "date")


def _names(record: AdvisoryRecord) -> list[tuple[str, str]]:
    names: list[tuple[str, str]] = []
    for product in record.products:
        names.append((product.product, product.field))
        if product.vendor:
            names.append((f"{product.vendor} {product.product}", product.field))
    for package in record.packages:
        names.append((package.name, package.field))
    if record.repository:
        names.append((record.repository.split("/")[-1], "source_code_location"))
    return names


def product_obs(records: Sequence[AdvisoryRecord], wanted: Sequence[str]) -> list[Obs]:
    obs: list[Obs] = []
    for record in records:
        names = _names(record)
        if not names:
            continue
        shown = sorted({name for name, _ in names if " " not in name} or {names[0][0]})
        accepts = any(names_match(w, name) for w in wanted for name, _ in names)
        obs.append(Obs(record.source, record.url, names[0][1], ", ".join(shown), accepts, shown))
    return obs


def identifier_decision(
    claim: IdentifierClaim, records: Sequence[AdvisoryRecord], text: str
) -> Decision:
    value = claim.value
    own = [r for r in records if value.id in r.ids or value.id in r.aliases]
    if not own:
        return Decision(
            "unclear", "no_source", note=f"No primary source has a record for {value.id}."
        )
    live = [r for r in own if not r.withdrawn]
    if not live:
        first = own[0]
        return Decision(
            "contradicted",
            note=f"{value.id} is marked withdrawn or rejected in {_sources_rec(own)}.",
            source_url=first.url,
            source_field="withdrawn",
            evidence=escape_excerpt(f"{value.id}: withdrawn"),
            correct_value={"withdrawn": True},
        )
    parts: list[Decision] = []
    first = live[0]
    parts.append(
        Decision(
            "verified",
            note=f"There is a record for {value.id} in {_sources_rec(live)}.",
            source_url=first.url,
            source_field="ids",
            evidence=escape_excerpt(f"id: {value.id}"),
        )
    )
    if value.product:
        parts.append(
            judge("product", product_obs(live, [value.product]), value.product, text, "product")
        )
    if value.aliases:
        known = sorted({i for r in live for i in (*r.ids, *r.aliases)} - {value.id})
        missing = [a for a in value.aliases if a not in known]
        obs = [
            Obs(
                r.source,
                r.url,
                "aliases",
                ", ".join(sorted({*r.ids, *r.aliases} - {value.id})) or "none",
                all(a in {*r.ids, *r.aliases} for a in value.aliases),
                known,
            )
            for r in live
            if r.aliases or r.source.startswith("github")
        ]
        decision = judge("aliases", obs, ", ".join(value.aliases), text, "aliases")
        if missing and decision.status == "verified":
            decision.status = "contradicted"
        parts.append(decision)
    return merge(parts)


def _sources_rec(records: Sequence[AdvisoryRecord]) -> str:
    return _sources([Obs(r.source, r.url, "", "", True, None) for r in records])


def product_decision(claim: ProductClaim, records: Sequence[AdvisoryRecord], text: str) -> Decision:
    wanted = [v for v in (claim.value.product, claim.value.package, claim.value.vendor) if v]
    return judge("product", product_obs(records, wanted), ", ".join(wanted), text, "product")


def taxonomy_decision(claim: TaxonomyClaim, lookup: Lookup | None) -> Decision:
    value = claim.value
    if lookup is None or lookup.atlas is None:
        failures = list(lookup.failures) if lookup else []
        return Decision("unclear", _failures_reason(failures), note=_failures_note(failures))
    atlas = lookup.atlas
    release = f"ATLAS {atlas.release}" + (
        " (synthetic pin from --sources)" if atlas.synthetic_pin else ""
    )
    entry = atlas.entry
    if entry is None:
        return Decision(
            "contradicted",
            note=f"{value.id} is not in {release}.",
            source_url=atlas.url,
            source_field="id",
            evidence=escape_excerpt(f"id: {value.id} not found"),
            correct_value={"exists": False},
        )
    parts = [
        Decision(
            "verified",
            note=f"{value.id} exists in {release}.",
            source_url=atlas.url,
            source_field="id",
            evidence=escape_excerpt(f"{entry.id}: {entry.name}"),
        )
    ]
    if value.name:
        same = norm_name(value.name) == norm_name(entry.name)
        parts.append(
            Decision(
                "verified" if same else "contradicted",
                note=f"{release} names {value.id} {entry.name!r}.",
                source_url=atlas.url,
                source_field="name",
                evidence=escape_excerpt(f"name: {entry.name}"),
                correct_value=None if same else {"name": entry.name},
            )
        )
    if value.tactic:
        tactics = [*entry.tactics, *entry.tactic_names]
        same = any(norm_name(value.tactic) == norm_name(t) for t in tactics)
        shown = (
            ", ".join(f"{i} {n}" for i, n in zip(entry.tactics, entry.tactic_names, strict=False))
            or "none"
        )
        parts.append(
            Decision(
                "verified" if same else "contradicted",
                note=f"{release} lists the tactics of {value.id} as {shown}.",
                source_url=atlas.url,
                source_field="tactics",
                evidence=escape_excerpt(f"tactics: {shown}"),
                correct_value=None if same else {"tactic": list(entry.tactic_names)},
            )
        )
    return merge(parts)


# --- entries -----------------------------------------------------------------------------------

_NOT_CHECKED = {
    "prose": "Prose claims are checked by the judge from V2.",
    "scope_payout": "Scope and payout claims need the official program page (judge, V2).",
    "decision": "An item awaiting David's decision; never checked.",
}


def _entry(claim: Claim, decision: Decision, checked_on: str) -> PackEntry:
    return PackEntry(
        claim_id=claim.claim_id,
        status=decision.status,
        reason=decision.reason if decision.status == "unclear" else None,
        note_path=claim.note_path,
        lines=claim.lines,
        claim=escape_excerpt(claim.text, CLAIM_LIMIT),
        type=claim.type,
        source_url=decision.source_url,
        source_field=decision.source_field,
        evidence=decision.evidence,
        note=escape_excerpt(decision.note, CLAIM_LIMIT * 2),
        correct_value=decision.correct_value if decision.status == "contradicted" else None,
        conflict=tuple(decision.conflict) if decision.conflict else None,
        checked_on=checked_on,
        warnings=tuple(dict.fromkeys(decision.warnings)),
    )


def decide(claim: Claim, context: ClaimContext) -> Decision:
    note = context.note
    if claim.type in _NOT_CHECKED:
        return Decision("unclear", "not_checked", note=_NOT_CHECKED[claim.type])
    if isinstance(claim, TaxonomyClaim):
        if claim.value.framework == "owasp":
            return Decision(
                "unclear",
                "not_checked",
                note="OWASP IDs are checked from V2, when the OWASP tables arrive.",
            )
        return taxonomy_decision(claim, context.lookups.get(claim.value.id))
    if isinstance(claim, DateClaim) and claim.value.kind not in ("published", "updated"):
        return Decision(
            "unclear",
            "not_checked",
            note=f"No structured source states the {claim.value.kind} date; "
            "the judge checks it from V2.",
        )
    ids = resolve_ids(claim, note, context.lookups)
    if ids == "ambiguous":
        return Decision(
            "unclear",
            "ambiguous",
            note="The claim names no advisory and the note's frontmatter names several.",
        )
    if ids == "no_source" or isinstance(ids, str):
        return Decision(
            "unclear",
            "no_source",
            note="The claim names no advisory and the note's frontmatter names none.",
        )
    records, failures = records_for(ids, context.lookups)
    if not records:
        return Decision("unclear", _failures_reason(failures), note=_failures_note(failures))
    text = section_text(note, claim.lines[0])
    if isinstance(claim, VersionClaim):
        decision = version_decision(claim, records, text)
    elif isinstance(claim, SeverityClaim):
        decision = severity_decision(claim, records, text)
    elif isinstance(claim, WeaknessClaim):
        decision = weakness_decision(claim, records, text)
    elif isinstance(claim, DateClaim):
        decision = date_decision(claim, records, text)
    elif isinstance(claim, IdentifierClaim):
        decision = identifier_decision(claim, records, text)
    elif isinstance(claim, ProductClaim):
        decision = product_decision(claim, records, text)
    else:  # pragma: no cover - every type is handled above
        return Decision("unclear", "not_checked")
    if decision.status == "unclear" and decision.reason == "no_source" and failures:
        decision.note += " " + _failures_note(failures)
    if any(r.withdrawn for r in records):
        decision.warnings.append("a source marks this advisory as withdrawn or rejected")
    return decision


def compare_claim(claim: Claim, context: ClaimContext) -> list[PackEntry]:
    """The claim's entry and, for an unrecorded conflict, the ``new_finding`` next to it."""
    decision = decide(claim, context)
    entries = [_entry(claim, decision, context.checked_on)]
    if decision.status == "verified" and decision.unrecorded_conflict and decision.conflict:
        entries.append(
            PackEntry(
                claim_id=f"{claim.claim_id}-n1",
                status="new_finding",
                note_path=claim.note_path,
                lines=claim.lines,
                claim=escape_excerpt(
                    f"Primary sources disagree on a value the note states without the conflict: "
                    f"{claim.text}",
                    CLAIM_LIMIT,
                ),
                type=claim.type,
                source_url=decision.conflict[0].source_url,
                source_field=decision.source_field,
                evidence=escape_excerpt(
                    "; ".join(f"{c.source_url}: {c.value}" for c in decision.conflict)
                ),
                note=escape_excerpt(decision.note, CLAIM_LIMIT * 2),
                conflict=tuple(decision.conflict),
                checked_on=context.checked_on,
            )
        )
    return entries
