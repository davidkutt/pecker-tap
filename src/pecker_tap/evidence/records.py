"""Normalised source records (V1 brief, deliverable 6).

Every structured source is turned into an ``AdvisoryRecord``: the fields the comparison needs, from
one API response, with that response's URL. Each field also names the source field it came from
(``FieldRef``), so a verdict can say exactly what it used.
"""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

SourceName = Literal["github_global", "github_repo", "cve_org", "nvd"]
FailureReason = Literal["unreachable", "no_source", "not_found", "bad_data", "blocked"]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Cvss(_Strict):
    version: str
    score: float | None = None
    vector: str | None = None
    label: str | None = None
    field: str


class AffectedPackage(_Strict):
    ecosystem: str | None = None
    name: str
    vulnerable_range: str | None = None
    patched: tuple[str, ...] = ()
    """Fixed versions; empty with ``patched_stated`` means the source says there is no fix."""
    patched_stated: bool = False
    field: str


class Product(_Strict):
    vendor: str | None = None
    product: str
    field: str


class AdvisoryRecord(_Strict):
    source: SourceName
    url: str
    ids: tuple[str, ...]
    """The record's own IDs (GHSA and/or CVE), canonical."""
    aliases: tuple[str, ...] = ()
    severity_label: str | None = None
    severity_field: str | None = None
    cvss: tuple[Cvss, ...] = ()
    cwes: tuple[str, ...] = ()
    cwe_field: str | None = None
    packages: tuple[AffectedPackage, ...] = ()
    products: tuple[Product, ...] = ()
    published: str | None = None
    published_field: str | None = None
    updated: str | None = None
    updated_field: str | None = None
    withdrawn: bool = False
    repository: str | None = None
    """``owner/repo`` of the source code, where the source names it."""
    repository_advisory_url: str | None = None


class SourceFailure(_Strict):
    source: str
    url: str
    reason: FailureReason
    detail: str = ""


class AtlasEntry(_Strict):
    id: str
    name: str
    object_type: str = ""
    tactics: tuple[str, ...] = ()
    tactic_names: tuple[str, ...] = ()
    case_studies: tuple[str, ...] = ()


class AtlasResult(_Strict):
    release: str
    url: str
    entry: AtlasEntry | None = None
    """``None`` when the ID is not in the pinned release."""
    synthetic_pin: bool = False


class Lookup(_Strict):
    """Everything found for one key (an advisory ID or an ATLAS ID)."""

    key: str
    records: tuple[AdvisoryRecord, ...] = ()
    atlas: AtlasResult | None = None
    failures: tuple[SourceFailure, ...] = ()
    warnings: tuple[str, ...] = Field(default=())
