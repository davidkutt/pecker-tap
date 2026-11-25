"""The pip-audit ignore list: reason and expiry per entry, at most 90 days ahead."""

from datetime import date, timedelta
from pathlib import Path

import pytest
from audit_ignores import (
    DEFAULT_FILE,
    MAX_DAYS,
    Ignore,
    IgnoreListError,
    load,
    main,
    pip_audit_args,
)

TODAY = date(2026, 11, 22)


def entry(
    vuln_id: str = "GHSA-abcd-efgh-ijkl", reason: str = "not reachable", expires: str = ""
) -> str:
    when = expires or (TODAY + timedelta(days=30)).isoformat()
    return f'[[ignore]]\nid = "{vuln_id}"\nreason = "{reason}"\nexpires = {when}\n'


def problems(text: str) -> tuple[str, ...]:
    with pytest.raises(IgnoreListError) as caught:
        load(text, TODAY)
    return caught.value.problems


def test_the_shipped_list_is_valid_and_empty() -> None:
    assert load(DEFAULT_FILE.read_text(encoding="utf-8"), TODAY) == []
    assert pip_audit_args([]) == []


def test_a_valid_entry_becomes_an_ignore_flag() -> None:
    entries = load(entry() + entry("PYSEC-2026-17", "dev tool only"), TODAY)
    assert entries == [
        Ignore("GHSA-abcd-efgh-ijkl", "not reachable", TODAY + timedelta(days=30)),
        Ignore("PYSEC-2026-17", "dev tool only", TODAY + timedelta(days=30)),
    ]
    assert pip_audit_args(entries) == [
        "--ignore-vuln=GHSA-abcd-efgh-ijkl",
        "--ignore-vuln=PYSEC-2026-17",
    ]


def test_expiry_from_today_up_to_ninety_days_is_accepted() -> None:
    assert load(entry(expires=TODAY.isoformat()), TODAY)
    assert load(entry(expires=(TODAY + timedelta(days=MAX_DAYS)).isoformat()), TODAY)


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (entry(reason=""), "ignore[0]: reason is missing"),
        (entry(reason="   "), "ignore[0]: reason is missing"),
        ('[[ignore]]\nid = "GHSA-a"\nexpires = 2026-12-01\n', "ignore[0]: reason is missing"),
        (entry(expires="2026-11-21"), "ignore[0]: expired on 2026-11-21, review it"),
        (entry(expires="2027-02-21"), "ignore[0]: expires more than 90 days ahead (2027-02-21)"),
        (entry(expires="2026-12-01T00:00:00Z"), "ignore[0]: expires must be a date (YYYY-MM-DD)"),
        (entry(expires='"2026-12-01"'), "ignore[0]: expires must be a date (YYYY-MM-DD)"),
        (
            '[[ignore]]\nid = "GHSA-a"\nreason = "r"\n',
            "ignore[0]: expires must be a date (YYYY-MM-DD)",
        ),
        (entry(vuln_id="nope"), "ignore[0]: id must look like GHSA-..., PYSEC-... or CVE-..."),
        (entry() + 'owner = "x"\n', "ignore[0]: unknown keys owner"),
        (entry() + entry(), "GHSA-abcd-efgh-ijkl: listed twice"),
        ('ignore = "GHSA-a"\n', "ignore must be a list of tables"),
        ("ignore = [1]\n", "ignore[0]: must be a table with id, reason and expires"),
        ("skip = []\n", "unknown top-level keys skip"),
    ],
)
def test_entries_breaking_a_rule_fail(text: str, expected: str) -> None:
    assert expected in problems(text)


def test_invalid_toml_fails() -> None:
    assert problems("ignore = [")[0].startswith("not valid TOML")


def test_main_prints_flags_or_fails(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    far = (date.today() + timedelta(days=10)).isoformat()
    good = tmp_path / "good.toml"
    good.write_text(entry(expires=far), encoding="utf-8")
    assert main([str(good)]) == 0
    captured = capsys.readouterr()
    assert captured.out.strip() == "--ignore-vuln=GHSA-abcd-efgh-ijkl"
    assert "ignoring GHSA-abcd-efgh-ijkl until" in captured.err
    bad = tmp_path / "bad.toml"
    bad.write_text(entry(expires="2020-01-01"), encoding="utf-8")
    assert main([str(bad)]) == 1
    assert "expired on 2020-01-01" in capsys.readouterr().err
