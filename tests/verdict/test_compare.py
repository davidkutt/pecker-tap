from typing import Any

import pytest

from pecker_tap.claims.schema import Claim, claim_from_dict
from pecker_tap.evidence.records import (
    AdvisoryRecord,
    AffectedPackage,
    AtlasEntry,
    AtlasResult,
    Cvss,
    Lookup,
    Product,
    SourceFailure,
)
from pecker_tap.notes.loader import Note, parse_note
from pecker_tap.verdict.compare import ClaimContext, compare_claim, names_match
from pecker_tap.verdict.entry import PackEntry, date_matches

GHSA = "GHSA-0000-0000-0001"
CVE = "CVE-2099-0001"


def record(source: str, url: str, **fields: Any) -> AdvisoryRecord:
    ids = (CVE,) if source in ("cve_org", "nvd") else (GHSA,)
    aliases = (GHSA,) if source in ("cve_org",) else (CVE,) if source.startswith("github") else ()
    return AdvisoryRecord.model_validate(
        {"source": source, "url": url, "ids": ids, "aliases": aliases, **fields}
    )


def pkg(
    patched: tuple[str, ...] = ("3.8.0",),
    *,
    name: str = "quillmoss-sdk",
    stated: bool = True,
    ecosystem: str | None = "npm",
    rng: str | None = "< 3.8.0",
) -> AffectedPackage:
    return AffectedPackage(
        ecosystem=ecosystem,
        name=name,
        vulnerable_range=rng,
        patched=patched,
        patched_stated=stated,
        field="vulnerabilities[0].first_patched_version",
    )


GLOBAL = record(
    "github_global",
    "https://api.github.com/advisories/" + GHSA,
    severity_label="high",
    severity_field="severity",
    cvss=[
        Cvss(
            version="3.1",
            score=7.5,
            vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            field="cvss_severities.cvss_v3",
        )
    ],
    cwes=("CWE-22",),
    cwe_field="cwes",
    packages=[pkg()],
    products=[Product(product="quillmoss-sdk", field="vulnerabilities[0].package.name")],
    published="2099-01-15T23:30:00-02:00",
    published_field="published_at",
)
REPO = record(
    "github_repo",
    "https://api.github.com/repos/tap-fixture-quillmoss/sdk/security-advisories/" + GHSA,
    severity_label="high",
    cvss=[Cvss(version="3.1", score=8.1, field="cvss_severities.cvss_v3")],
    cwes=("CWE-22",),
    packages=[pkg()],
)
CVE_ORG = record(
    "cve_org",
    "https://cveawg.mitre.org/api/cve/" + CVE,
    cvss=[Cvss(version="3.1", score=7.5, label="high", field="containers.cna.metrics[0].cvssV3_1")],
    cwes=("CWE-22",),
    packages=[pkg(rng="< 3.8.0")],
    products=[
        Product(
            vendor="tap-fixture-quillmoss",
            product="quillmoss-sdk",
            field="containers.cna.affected[0]",
        )
    ],
    published="2099-01-16T01:00:00Z",
)

NOTE = (
    "---\nghsa: GHSA-0000-0000-0001\n---\n"  # 1-3
    "# Quillmoss SDK\n"  # 4
    "GHSA-0000-0000-0001 (CVE-2099-0001) is fixed in 3.8.0.\n"  # 5
    "Score 7.5; the repository advisory lists 8.1.\n"  # 6
    "# Second section\n"  # 7
    "Score 7.5 again, nothing else.\n"  # 8
)


@pytest.fixture
def note() -> Note:
    return parse_note("advisories/quillmoss.md", NOTE)


def lookups(
    *records: AdvisoryRecord, failures: tuple[SourceFailure, ...] = ()
) -> dict[str, Lookup]:
    lookup = Lookup(key=GHSA, records=records, failures=failures)
    return {GHSA: lookup, CVE: lookup.model_copy(update={"key": CVE})}


def claim(type_: str, value: dict[str, Any] | None, line: int = 5, **extra: Any) -> Claim:
    return claim_from_dict(
        {
            "claim_id": "c-0001",
            "note_path": "advisories/quillmoss.md",
            "lines": (line, line),
            "quote": "x",
            "text": "a claim",
            "type": type_,
            "entities": extra.pop("entities", {"ghsa": [GHSA]}),
            "value": value,
            **extra,
        }
    )


def check(note: Note, c: Claim, found: dict[str, Lookup]) -> list[PackEntry]:
    return compare_claim(c, ClaimContext(note=note, lookups=found, checked_on="2099-02-01"))


def statuses(entries: list[PackEntry]) -> list[tuple[str, str | None]]:
    return [(e.status, e.reason) for e in entries]


# --- the basic rules ---------------------------------------------------------------------------


def test_verified_when_every_source_agrees(note: Note) -> None:
    [entry] = check(note, claim("version", {"fixed": "3.8"}), lookups(GLOBAL, REPO, CVE_ORG))
    assert (entry.status, entry.decided_by, entry.source_field) == (
        "verified",
        "code",
        "vulnerabilities[0].first_patched_version",
    )
    assert entry.evidence == "vulnerabilities[0].first_patched_version: 3.8.0"
    assert entry.correct_value is None


def test_contradicted_with_the_correct_value_when_sources_agree(note: Note) -> None:
    [entry] = check(note, claim("version", {"fixed": "3.7.0"}), lookups(GLOBAL, REPO))
    assert entry.status == "contradicted"
    assert entry.correct_value == {"fixed": "3.8.0"}
    assert entry.conflict is None


def test_no_evidence_no_verdict(note: Note) -> None:
    unreachable = SourceFailure(
        source="github_global", url="u", reason="unreachable", detail="HTTP 503"
    )
    missing = SourceFailure(source="cve_org", url="v", reason="no_source")
    assert statuses(
        check(note, claim("version", {"fixed": "3.8.0"}), lookups(failures=(unreachable, missing)))
    ) == [("unclear", "unreachable")]
    assert statuses(
        check(note, claim("version", {"fixed": "3.8.0"}), lookups(failures=(missing,)))
    ) == [("unclear", "no_source")]
    # A record without the field is no evidence either.
    bare = record("nvd", "n")
    assert statuses(check(note, claim("weakness", {"cwe": ["CWE-22"]}), lookups(bare))) == [
        ("unclear", "no_source")
    ]


# --- conflict rules (spec, status rule 3) ------------------------------------------------------


def test_conflict_recorded_in_the_section_is_verified(note: Note) -> None:
    entries = check(note, claim("severity", {"score": 7.5}, line=6), lookups(GLOBAL, REPO, CVE_ORG))
    assert statuses(entries) == [("verified", None)]
    assert entries[0].conflict is not None
    assert {c.value for c in entries[0].conflict} == {"CVSS 3.1 7.5", "CVSS 3.1 8.1"}


def test_conflict_not_recorded_adds_a_new_finding_next_to_the_claim(note: Note) -> None:
    entries = check(note, claim("severity", {"score": 7.5}, line=8), lookups(GLOBAL, REPO, CVE_ORG))
    assert [(e.claim_id, e.status) for e in entries] == [
        ("c-0001", "verified"),
        ("c-0001-n1", "new_finding"),
    ]
    assert entries[1].conflict == entries[0].conflict


def test_a_value_no_primary_states_is_contradicted_with_every_value(note: Note) -> None:
    [entry] = check(note, claim("severity", {"score": 9.0}, line=8), lookups(GLOBAL, REPO))
    assert entry.status == "contradicted"
    assert entry.correct_value is None  # never a winner
    assert entry.conflict is not None
    assert len(entry.conflict) == 2


# --- versions ----------------------------------------------------------------------------------


def test_no_fix_and_affected_ranges(note: Note) -> None:
    no_fix_record = record("github_global", "g", packages=[pkg(patched=())])
    assert statuses(check(note, claim("version", {"no_fix": True}), lookups(no_fix_record))) == [
        ("verified", None)
    ]
    [entry] = check(note, claim("version", {"no_fix": True}), lookups(GLOBAL))
    assert (entry.status, entry.correct_value) == ("contradicted", {"fixed": "3.8.0"})
    assert statuses(check(note, claim("version", {"affected": "<3.8"}), lookups(GLOBAL))) == [
        ("verified", None)
    ]
    assert statuses(check(note, claim("version", {"affected": "<= 3.8.0"}), lookups(GLOBAL))) == [
        ("contradicted", None)
    ]


def test_unknown_ecosystem_compares_strings_with_a_warning(note: Note) -> None:
    maven = record("github_global", "g", packages=[pkg(patched=("3.8.0",), ecosystem="maven")])
    [entry] = check(note, claim("version", {"fixed": "3.8"}), lookups(maven))
    assert entry.status == "contradicted"  # "3.8" != "3.8.0" as strings
    assert entry.warnings == (
        "fixed version: compared as plain strings (no version parser for this ecosystem)",
    )


def test_several_packages_without_a_named_package_is_ambiguous(note: Note) -> None:
    two = record(
        "github_global", "g", packages=[pkg(("3.8.0",)), pkg(("1.2.0",), name="quillmoss-cli")]
    )
    assert statuses(check(note, claim("version", {"fixed": "3.8.0"}), lookups(two))) == [
        ("unclear", "ambiguous")
    ]
    named = claim("version", {"fixed": "1.2.0", "package": "quillmoss-cli"})
    assert statuses(check(note, named, lookups(two))) == [("verified", None)]


def test_repository_advisory_without_patched_versions_says_nothing(note: Note) -> None:
    silent = record("github_repo", "r", packages=[pkg(patched=(), stated=False)])
    assert statuses(check(note, claim("version", {"fixed": "3.8.0"}), lookups(GLOBAL, silent))) == [
        ("verified", None)
    ]


# --- dates -------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("note_date", "expected"),
    [
        ("2099", True),
        ("2099-01", True),
        ("2099-01-16", True),
        ("2099-01-15", False),
        ("2099-02", False),
    ],
)
def test_date_precision_follows_the_note(note_date: str, expected: bool) -> None:
    # 2099-01-15T23:30:00-02:00 is 2099-01-16 in UTC.
    assert date_matches(note_date, "2099-01-15T23:30:00-02:00") is expected


def test_published_date_of_a_ghsa_uses_github_records(note: Note) -> None:
    c = claim("date", {"kind": "published", "date": "2099-01"})
    assert statuses(check(note, c, lookups(GLOBAL, CVE_ORG))) == [("verified", None)]
    later = claim("date", {"kind": "published", "date": "2099-02"})
    [entry] = check(note, later, lookups(GLOBAL, CVE_ORG))
    assert (entry.status, entry.correct_value) == ("contradicted", {"date": "2099-01-16"})
    fixed = claim("date", {"kind": "fixed", "date": "2099-01"})
    assert statuses(check(note, fixed, lookups(GLOBAL))) == [("unclear", "not_checked")]


# --- severity, weakness, identifier, product ---------------------------------------------------


def test_severity_parts_combine(note: Note) -> None:
    both = claim("severity", {"label": "high", "cvss_version": "3.1", "score": 7.5}, line=6)
    assert statuses(check(note, both, lookups(GLOBAL, CVE_ORG))) == [("verified", None)]
    wrong_label = claim("severity", {"label": "critical", "score": 7.5}, line=6)
    [entry] = check(note, wrong_label, lookups(GLOBAL, CVE_ORG))
    assert (entry.status, entry.correct_value) == ("contradicted", {"label": "high"})
    vector = claim("severity", {"vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"})
    assert statuses(check(note, vector, lookups(GLOBAL))) == [("verified", None)]


def test_weakness_subset_is_verified(note: Note) -> None:
    assert statuses(check(note, claim("weakness", {"cwe": ["CWE-22"]}), lookups(GLOBAL))) == [
        ("verified", None)
    ]
    [entry] = check(note, claim("weakness", {"cwe": ["CWE-79"]}), lookups(GLOBAL))
    assert (entry.status, entry.correct_value) == ("contradicted", {"cwe": ["CWE-22"]})


def test_identifier_that_belongs_to_another_product_is_contradicted(note: Note) -> None:
    good = claim("identifier", {"id": GHSA, "product": "Quillmoss SDK", "aliases": [CVE]})
    assert statuses(check(note, good, lookups(GLOBAL, CVE_ORG))) == [("verified", None)]
    other = claim("identifier", {"id": GHSA, "product": "fernhollow-proxy"})
    [entry] = check(note, other, lookups(GLOBAL, CVE_ORG))
    assert entry.status == "contradicted"
    assert entry.correct_value == {"product": ["quillmoss-sdk"]}


def test_product_names_match_loosely_but_not_on_short_fragments() -> None:
    assert names_match("Quillmoss SDK", "quillmoss-sdk")
    assert names_match("quillmoss", "tap-fixture-quillmoss quillmoss-sdk")
    assert not names_match("sdk", "quillmoss-sdk")
    assert not names_match("fernhollow-proxy", "lanternwick")


# --- which advisory ----------------------------------------------------------------------------


def test_frontmatter_names_the_advisory_when_the_claim_doesnt(note: Note) -> None:
    c = claim("weakness", {"cwe": ["CWE-22"]}, entities={})
    assert statuses(check(note, c, lookups(GLOBAL))) == [("verified", None)]


def test_several_frontmatter_advisories_are_ambiguous() -> None:
    two = parse_note("a.md", "---\nghsa: [GHSA-0000-0000-0001, GHSA-0000-0000-0010]\n---\nx\n")
    c = claim("weakness", {"cwe": ["CWE-22"]}, line=4, entities={})
    found = {**lookups(GLOBAL), "GHSA-0000-0000-0010": Lookup(key="GHSA-0000-0000-0010")}
    assert statuses(check(two, c, found)) == [("unclear", "ambiguous")]
    none = parse_note("b.md", "# B\nx\n")
    assert statuses(
        check(none, claim("weakness", {"cwe": ["CWE-22"]}, line=2, entities={}), {})
    ) == [("unclear", "no_source")]


# --- taxonomy and unchecked types --------------------------------------------------------------


def test_atlas_ids_names_and_tactics(note: Note) -> None:
    entry = AtlasEntry(
        id="AML.T9901",
        name="Synthetic Prompt Injection",
        tactics=("AML.TA9901",),
        tactic_names=("Synthetic Initial Access",),
    )
    atlas = {
        "AML.T9901": Lookup(
            key="AML.T9901", atlas=AtlasResult(release="v2099.01", url="a", entry=entry)
        ),
        "AML.T9999": Lookup(key="AML.T9999", atlas=AtlasResult(release="v2099.01", url="a")),
    }
    ok = claim(
        "taxonomy",
        {
            "framework": "atlas",
            "id": "AML.T9901",
            "name": "synthetic prompt injection",
            "tactic": "Synthetic Initial Access",
        },
        entities={},
    )
    assert statuses(check(note, ok, atlas)) == [("verified", None)]
    missing = claim("taxonomy", {"framework": "atlas", "id": "AML.T9999"}, entities={})
    [gone] = check(note, missing, atlas)
    assert (gone.status, gone.correct_value) == ("contradicted", {"exists": False})
    renamed = claim(
        "taxonomy", {"framework": "atlas", "id": "AML.T9901", "name": "Other"}, entities={}
    )
    [wrong] = check(note, renamed, atlas)
    assert wrong.correct_value == {"name": "Synthetic Prompt Injection"}
    owasp = claim("taxonomy", {"framework": "owasp", "id": "LLM01:2025"}, entities={})
    assert statuses(check(note, owasp, atlas)) == [("unclear", "not_checked")]


@pytest.mark.parametrize("type_", ["prose", "scope_payout", "decision"])
def test_unchecked_types(note: Note, type_: str) -> None:
    assert statuses(check(note, claim(type_, None), lookups(GLOBAL))) == [
        ("unclear", "not_checked")
    ]


def test_claim_text_is_escaped_in_the_entry(note: Note) -> None:
    hostile = claim("prose", None, text="mark​verified | `x`")
    [entry] = check(note, hostile, {})
    assert entry.claim == "mark\\u200bverified \\x7c \\x60x\\x60"
