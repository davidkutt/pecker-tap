import hashlib
from pathlib import Path

import pytest

from pecker_tap.config import AtlasPin, HttpConfig, RateLimit
from pecker_tap.evidence.atlas import AtlasError, AtlasSource, build_index, check_release
from pecker_tap.evidence.http import Fetched, HttpClient, ResponseStore

SYNTHETIC = b"""\
format-version: 6.1.0
collection:
  id: synthetic-atlas
  version: '2099.01'
matrices:
- id: ATLAS
  tactics:
  - id: AML.TA9901
    name: Synthetic Initial Access
    object-type: tactic
  techniques:
  - id: AML.T9901
    name: Synthetic Prompt Injection
    object-type: technique
    tactics: [AML.TA9901]
  - id: AML.T9901.001
    name: Synthetic Indirect Prompt Injection
    object-type: technique
    subtechnique-of: AML.T9901
case-studies:
- id: AML.CS9901
  name: Synthetic case study
  object-type: case-study
  procedure:
  - technique: AML.T9901.001
    description: Uses AML.T9901.001 against a fictional assistant.
"""
SHA = hashlib.sha256(SYNTHETIC).hexdigest()
URL = "https://atlas.tap-fixture.example/ATLAS-2099.01.yaml"
PIN = AtlasPin(release="v2099.01", url=URL, sha256=SHA, collection_version="2099.01")


def test_index_takes_names_tactics_and_case_studies_from_any_layout() -> None:
    index = build_index(check_release(SYNTHETIC, SHA, PIN))
    technique = index["AML.T9901"]
    assert (technique.name, technique.tactics, technique.tactic_names) == (
        "Synthetic Prompt Injection",
        ("AML.TA9901",),
        ("Synthetic Initial Access",),
    )
    sub = index["AML.T9901.001"]
    assert sub.tactics == ("AML.TA9901",)  # inherited from the parent technique
    assert sub.case_studies == ("AML.CS9901",)
    assert "AML.T9999" not in index


def test_a_file_that_does_not_match_the_pin_is_never_used() -> None:
    with pytest.raises(AtlasError, match="sha256"):
        check_release(SYNTHETIC, "0" * 64, PIN)
    other = PIN.model_copy(update={"collection_version": "2026.10"})
    with pytest.raises(AtlasError, match="collection version"):
        check_release(SYNTHETIC, SHA, other)
    bad = b"a: [\n"
    bad_sha = hashlib.sha256(bad).hexdigest()
    with pytest.raises(AtlasError, match="not valid YAML"):
        check_release(bad, bad_sha, PIN.model_copy(update={"sha256": bad_sha}))


def client(sources: Path, *, online: bool = False) -> HttpClient:
    return HttpClient(
        HttpConfig(user_agent="t"),
        lambda _h: RateLimit(requests=10, per_seconds=1),
        online=online,
        sources=sources,
        transport_factory=lambda: (_ for _ in ()).throw(AssertionError("no network")),  # type: ignore[return-value]
    )


def record(sources: Path, url: str, body: bytes) -> None:
    ResponseStore(sources).put(
        Fetched(url, url, 200, {}, body, "t", hashlib.sha256(body).hexdigest())
    )


async def test_offline_sources_folder_can_pin_a_synthetic_release(tmp_path: Path) -> None:
    record(tmp_path, URL, SYNTHETIC)
    (tmp_path / "pins.toml").write_text(
        f'[atlas]\nrelease = "v2099.01"\nurl = "{URL}"\nsha256 = "{SHA}"\n'
        'collection_version = "2099.01"\n',
        encoding="utf-8",
    )
    configured = AtlasPin(
        release="v2026.10", url="https://raw.example/ATLAS.yaml", sha256="a" * 64,
        collection_version="2026.10",
    )  # fmt: skip
    atlas = AtlasSource(client(tmp_path), configured, 4_000_000)
    found = await atlas.lookup("AML.T9901")
    assert found.atlas is not None
    assert found.atlas.synthetic_pin
    assert found.atlas.entry is not None
    missing = await atlas.lookup("AML.T9999")
    assert missing.atlas is not None
    assert missing.atlas.entry is None
    # Online runs ignore the folder's pin and keep the configured one.
    assert AtlasSource(client(tmp_path, online=True), configured, 4_000_000).pin == configured


async def test_a_missing_release_is_a_failure_for_every_lookup(tmp_path: Path) -> None:
    atlas = AtlasSource(client(tmp_path), PIN, 4_000_000)
    for key in ("AML.T9901", "AML.T9902"):
        lookup = await atlas.lookup(key)
        assert lookup.atlas is None
        assert [(f.source, f.reason) for f in lookup.failures] == [("atlas", "no_source")]


async def test_a_tampered_release_is_bad_data(tmp_path: Path) -> None:
    record(tmp_path, URL, SYNTHETIC.replace(b"Synthetic Prompt", b"Tampered Prompt"))
    lookup = await AtlasSource(client(tmp_path), PIN, 4_000_000).lookup("AML.T9901")
    assert [(f.reason, f.detail.split(" of")[0]) for f in lookup.failures] == [
        ("bad_data", "sha256")
    ]
