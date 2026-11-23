from typing import Any

import pytest

from pecker_tap.claims.check import check_claim
from pecker_tap.claims.schema import RejectedClaim, VersionClaim
from pecker_tap.notes.loader import Note, parse_note

NOTE_TEXT = (
    "---\n"  # 1
    "ghsa: GHSA-0000-0000-0001\n"  # 2
    "---\n"  # 3
    "# Quillmoss SDK path traversal\n"  # 4
    "GHSA-0000-0000-0001 (CVE-2099-0001) is fixed in 3.8.0.\n"  # 5
    "Mapped to AML.T9901 and LLM01:2025. Source: https://vendor.example/advisory\n"  # 6
    "Scored CVSS 3.1 7.5 (high), CWE-22.\n"  # 7
)


@pytest.fixture
def note() -> Note:
    return parse_note("advisories/quillmoss.md", NOTE_TEXT)


def raw(**overrides: Any) -> dict[str, Any]:
    claim: dict[str, Any] = {
        "first_line": 5,
        "last_line": 5,
        "quote": "is fixed in 3.8.0",
        "text": "GHSA-0000-0000-0001 is fixed in quillmoss-sdk 3.8.0.",
        "type": "version",
        "entities": {"ghsa": ["ghsa-0000-0000-0001"], "cve": ["CVE-2099-0001"]},
        "cited_urls": [],
        "value": {"fixed": "3.8.0"},
    }
    claim.update(overrides)
    return claim


def rejected(result: object) -> RejectedClaim:
    assert isinstance(result, RejectedClaim), result
    return result


def test_a_good_claim_is_kept_with_canonical_ids(note: Note) -> None:
    claim = check_claim(raw(), note, "c-0001")
    assert isinstance(claim, VersionClaim)
    assert claim.entities.ghsa == ("GHSA-0000-0000-0001",)
    assert claim.value.fixed == "3.8.0"
    assert claim.lines == (5, 5)


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"status": "verified"}, "schema"),
        ({"value": {"fixed": "3.8.0", "verdict": "verified"}}, "schema"),
        ({"first_line": "five"}, "schema"),
        ({"type": "opinion"}, "unknown_type"),
        ({"first_line": 0}, "bad_lines"),
        ({"first_line": 6, "last_line": 5}, "bad_lines"),
        ({"last_line": 99}, "bad_lines"),
        ({"quote": "is fixed in 3.9.0"}, "quote_not_found"),
        ({"quote": "is fixed in 3.8.0", "first_line": 6, "last_line": 7}, "quote_not_found"),
        ({"quote": "   "}, "quote_not_found"),
        ({"entities": {"ghsa": ["GHSA-1234"]}}, "bad_entity_id"),
        ({"entities": {"cve": ["CVE-2099-0002"]}}, "entity_not_in_note"),
        ({"cited_urls": ["https://attacker.invalid/"]}, "url_not_in_note"),
        ({"entities": {"urls": ["https://other.example/"]}}, "url_not_in_note"),
        ({"value": None}, "bad_value"),
        ({"value": {"fixed": "3.8.0", "affected": "< 3.8.0"}}, "bad_value"),
        ({"type": "severity", "value": {"score": 11.0}}, "bad_value"),
        ({"type": "date", "value": {"kind": "published", "date": "Nov 2026"}}, "bad_value"),
        ({"type": "identifier", "value": {"id": "CVE-2099-0009"}}, "entity_not_in_note"),
    ],
)
def test_each_check_rejects_with_its_reason(
    note: Note, overrides: dict[str, Any], reason: str
) -> None:
    result = rejected(check_claim(raw(**overrides), note))
    assert result.reason == reason
    assert result.note_path == "advisories/quillmoss.md"


def test_rejection_detail_names_fields_never_the_text(note: Note) -> None:
    result = rejected(check_claim(raw(status="SECRET-MARKER-123"), note))
    assert "status" in result.detail
    assert "SECRET-MARKER-123" not in result.detail


def test_non_mapping_claim_is_a_schema_rejection(note: Note) -> None:
    assert rejected(check_claim("not a claim", note)).reason == "schema"


def test_typed_values_per_type(note: Note) -> None:
    severity = check_claim(
        raw(
            first_line=7,
            last_line=7,
            quote="CVSS 3.1 7.5 (high)",
            type="severity",
            value={"label": "Moderate", "cvss_version": "3.1", "score": 7.5, "fixed": "x"},
        ),
        note,
    )
    assert not isinstance(severity, RejectedClaim)
    # moderate is GitHub's word for medium; fields of other types are dropped, not kept.
    assert severity.model_dump()["value"] == {
        "label": "medium",
        "cvss_version": "3.1",
        "score": 7.5,
        "vector": None,
    }
    taxonomy = check_claim(
        raw(
            first_line=6,
            last_line=6,
            quote="AML.T9901",
            type="taxonomy",
            entities={},
            value={"framework": "atlas", "id": "aml.t9901"},
        ),
        note,
    )
    assert not isinstance(taxonomy, RejectedClaim)
    assert taxonomy.entities.atlas == ("AML.T9901",)  # value IDs join the entities
    prose = check_claim(raw(type="prose", value={"fixed": "3.8.0"}), note)
    assert not isinstance(prose, RejectedClaim)
    assert prose.value is None


def test_url_written_in_the_note_is_accepted(note: Note) -> None:
    claim = check_claim(
        raw(
            first_line=6,
            last_line=6,
            quote="Source: https://vendor.example/advisory",
            type="prose",
            value=None,
            cited_urls=["https://vendor.example/advisory"],
        ),
        note,
    )
    assert not isinstance(claim, RejectedClaim)
    assert claim.cited_urls == ("https://vendor.example/advisory",)
