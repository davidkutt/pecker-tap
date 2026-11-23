from test_compare import CVE, CVE_ORG, GHSA, GLOBAL, REPO

from pecker_tap.claims.schema import claim_from_dict
from pecker_tap.evidence.records import Lookup
from pecker_tap.notes.loader import parse_note
from pecker_tap.verdict.findings import missing_facts, named_advisories


def lookups() -> dict[str, Lookup]:
    lookup = Lookup(key=GHSA, records=(GLOBAL, REPO, CVE_ORG))
    return {GHSA: lookup, CVE: lookup.model_copy(update={"key": CVE})}


def test_one_entry_per_advisory_lists_every_missing_field() -> None:
    note = parse_note("a.md", "# A\nGHSA-0000-0000-0001 affects the SDK.\n")
    [entry] = missing_facts(note, [], lookups(), "2099-02-01", start=1)
    assert (entry.claim_id, entry.status, entry.lines) == ("n-0001", "new_finding", (2, 2))
    assert entry.correct_value == {
        "severity": {"label": "high", "cvss_version": "3.1", "score": 7.5},
        "fixed": "3.8.0",
        "cwe": ["CWE-22"],
        "alias": [CVE],
    }
    assert entry.evidence == (
        "severity: high / CVSS 3.1 7.5; fixed: 3.8.0; cwe: CWE-22; alias: CVE-2099-0001"
    )
    assert entry.note.startswith("Values taken severity from GitHub global advisory")


def test_fields_the_note_states_by_claim_or_by_value_are_not_listed() -> None:
    note = parse_note(
        "a.md",
        "# A\nGHSA-0000-0000-0001 (CVE-2099-0001) is fixed in 3.8.0, CWE-22.\nIt is serious.\n",
    )
    severity = claim_from_dict(
        {
            "claim_id": "c-0001",
            "note_path": "a.md",
            "lines": (3, 3),
            "quote": "serious",
            "text": "It is serious.",
            "type": "severity",
            "entities": {"ghsa": [GHSA]},
            "value": {"label": "high"},
        }
    )
    assert missing_facts(note, [severity], lookups(), "2099-02-01", start=1) == []
    without_claim = missing_facts(note, [], lookups(), "2099-02-01", start=7)
    assert [(e.claim_id, list(e.correct_value or {})) for e in without_claim] == [
        ("n-0007", ["severity"])
    ]


def test_ids_of_one_advisory_are_grouped_and_ordered_by_first_mention() -> None:
    note = parse_note("a.md", "# A\nCVE-2099-0001 first, later GHSA-0000-0000-0001.\n")
    assert named_advisories(note, []) == [CVE, GHSA]
    entries = missing_facts(note, [], lookups(), "2099-02-01", start=1)
    assert len(entries) == 1  # one advisory, two names
    assert "alias" not in (entries[0].correct_value or {})  # both IDs are written


def test_no_records_no_finding() -> None:
    note = parse_note("a.md", "# A\nGHSA-0000-0000-0001.\n")
    assert missing_facts(note, [], {GHSA: Lookup(key=GHSA)}, "2099-02-01", start=1) == []
