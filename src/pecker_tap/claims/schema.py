"""The claim model (spec, Claims) and the shape the extractor returns.

A ``Claim`` is a discriminated union over ``type``: every structured type has its own typed
``value`` model, and prose, scope/payout and decision claims carry ``value: null``. Unknown fields
are rejected everywhere.

The extractor (an LLM) never produces a ``Claim`` directly. It returns ``ExtractedClaim`` objects
with a flat, permissive ``value``; ``claims.check`` validates each one against the note and turns
it into a ``Claim`` or a ``RejectedClaim``. The flat shape keeps the JSON schema the model sees
simple, and one bad claim never costs the rest of its section.
"""

from __future__ import annotations

import re
from typing import Annotated, Literal, Self

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationInfo,
    field_validator,
    model_validator,
)

from pecker_tap.claims.patterns import CWE, canonical, matches

ClaimType = Literal[
    "identifier",
    "severity",
    "weakness",
    "version",
    "date",
    "product",
    "taxonomy",
    "scope_payout",
    "prose",
    "decision",
]
CLAIM_TYPES: tuple[ClaimType, ...] = (
    "identifier",
    "severity",
    "weakness",
    "version",
    "date",
    "product",
    "taxonomy",
    "scope_payout",
    "prose",
    "decision",
)
DateKind = Literal["published", "updated", "fixed", "disclosed", "reported"]
SeverityLabel = Literal["low", "medium", "high", "critical"]
CvssVersion = Literal["2.0", "3.0", "3.1", "4.0"]

_DATE = re.compile(r"\d{4}(?:-(?:0[1-9]|1[0-2])(?:-(?:0[1-9]|[12]\d|3[01]))?)?")


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


# --- typed values ------------------------------------------------------------------------------


class VersionValue(Strict):
    """Exactly one of ``fixed``, ``affected`` or ``no_fix``; ``package`` if the note names it."""

    fixed: str | None = None
    affected: str | None = None
    no_fix: Literal[True] | None = None
    package: str | None = None

    @model_validator(mode="after")
    def _one_fact(self) -> Self:
        set_fields = [name for name in ("fixed", "affected", "no_fix") if getattr(self, name)]
        if len(set_fields) != 1:
            msg = "a version value needs exactly one of fixed, affected or no_fix"
            raise ValueError(msg)
        return self


class SeverityValue(Strict):
    label: SeverityLabel | None = None
    cvss_version: CvssVersion | None = None
    score: Annotated[float, Field(ge=0.0, le=10.0)] | None = None
    vector: str | None = None

    @field_validator("label", mode="before")
    @classmethod
    def _moderate_is_medium(cls, value: object) -> object:
        if isinstance(value, str):
            lowered = value.strip().lower()
            return "medium" if lowered == "moderate" else lowered
        return value

    @model_validator(mode="after")
    def _something_to_check(self) -> Self:
        if self.label is None and self.score is None and not self.vector:
            msg = "a severity value needs a label, a score or a vector"
            raise ValueError(msg)
        return self


class WeaknessValue(Strict):
    cwe: Annotated[tuple[str, ...], Field(min_length=1)]

    @field_validator("cwe")
    @classmethod
    def _cwe_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        if not all(CWE.fullmatch(item.strip()) for item in value):
            msg = "every weakness must be a CWE ID such as CWE-79"
            raise ValueError(msg)
        return tuple(dict.fromkeys(canonical("cwe", item) for item in value))


class DateValue(Strict):
    kind: DateKind
    date: str
    """``YYYY``, ``YYYY-MM`` or ``YYYY-MM-DD``: as precise as the note."""

    @field_validator("date")
    @classmethod
    def _date_precision(cls, value: str) -> str:
        if not _DATE.fullmatch(value.strip()):
            msg = "date must be YYYY, YYYY-MM or YYYY-MM-DD"
            raise ValueError(msg)
        return value.strip()


class IdentifierValue(Strict):
    id: str
    product: str | None = None
    aliases: tuple[str, ...] = ()

    @field_validator("id")
    @classmethod
    def _advisory_id(cls, value: str) -> str:
        if matches("cve", value):
            return canonical("cve", value)
        if matches("ghsa", value):
            return canonical("ghsa", value)
        msg = "id must be a CVE or GHSA ID"
        raise ValueError(msg)

    @field_validator("aliases")
    @classmethod
    def _alias_ids(cls, value: tuple[str, ...]) -> tuple[str, ...]:
        result: list[str] = []
        for item in value:
            if matches("cve", item):
                result.append(canonical("cve", item))
            elif matches("ghsa", item):
                result.append(canonical("ghsa", item))
            else:
                msg = "aliases must be CVE or GHSA IDs"
                raise ValueError(msg)
        return tuple(result)


class ProductValue(Strict):
    product: str | None = None
    vendor: str | None = None
    package: str | None = None

    @model_validator(mode="after")
    def _something_to_check(self) -> Self:
        if not (self.product or self.vendor or self.package):
            msg = "a product value needs a product, vendor or package"
            raise ValueError(msg)
        return self


class TaxonomyValue(Strict):
    framework: Literal["atlas", "owasp"]
    id: str
    name: str | None = None
    tactic: str | None = None

    @field_validator("id")
    @classmethod
    def _id_matches_framework(cls, value: str, info: ValidationInfo) -> str:
        framework = info.data.get("framework")
        if framework not in ("atlas", "owasp"):
            return value  # the framework error is reported on its own
        if not matches(framework, value):
            hint = "an AML ID" if framework == "atlas" else "an OWASP ID with year"
            msg = f"taxonomy id must be {hint}"
            raise ValueError(msg)
        return canonical(framework, value)


# --- claims ------------------------------------------------------------------------------------


class Entities(Strict):
    ghsa: tuple[str, ...] = ()
    cve: tuple[str, ...] = ()
    atlas: tuple[str, ...] = ()
    owasp: tuple[str, ...] = ()
    urls: tuple[str, ...] = ()


class _ClaimBase(Strict):
    claim_id: str
    note_path: str
    lines: tuple[int, int]
    quote: str
    text: str
    entities: Entities = Field(default_factory=Entities)
    cited_urls: tuple[str, ...] = ()


class IdentifierClaim(_ClaimBase):
    type: Literal["identifier"] = "identifier"
    value: IdentifierValue


class SeverityClaim(_ClaimBase):
    type: Literal["severity"] = "severity"
    value: SeverityValue


class WeaknessClaim(_ClaimBase):
    type: Literal["weakness"] = "weakness"
    value: WeaknessValue


class VersionClaim(_ClaimBase):
    type: Literal["version"] = "version"
    value: VersionValue


class DateClaim(_ClaimBase):
    type: Literal["date"] = "date"
    value: DateValue


class ProductClaim(_ClaimBase):
    type: Literal["product"] = "product"
    value: ProductValue


class TaxonomyClaim(_ClaimBase):
    type: Literal["taxonomy"] = "taxonomy"
    value: TaxonomyValue


class ScopePayoutClaim(_ClaimBase):
    type: Literal["scope_payout"] = "scope_payout"
    value: None = None


class ProseClaim(_ClaimBase):
    type: Literal["prose"] = "prose"
    value: None = None


class DecisionClaim(_ClaimBase):
    type: Literal["decision"] = "decision"
    value: None = None


Claim = Annotated[
    IdentifierClaim
    | SeverityClaim
    | WeaknessClaim
    | VersionClaim
    | DateClaim
    | ProductClaim
    | TaxonomyClaim
    | ScopePayoutClaim
    | ProseClaim
    | DecisionClaim,
    Field(discriminator="type"),
]
CLAIM_ADAPTER: TypeAdapter[Claim] = TypeAdapter(Claim)

VALUE_MODELS: dict[str, type[Strict] | None] = {
    "identifier": IdentifierValue,
    "severity": SeverityValue,
    "weakness": WeaknessValue,
    "version": VersionValue,
    "date": DateValue,
    "product": ProductValue,
    "taxonomy": TaxonomyValue,
    "scope_payout": None,
    "prose": None,
    "decision": None,
}


def claim_from_dict(data: object) -> Claim:
    return CLAIM_ADAPTER.validate_python(data)


def advisory_ids(claim: Claim) -> list[str]:
    """CVE and GHSA IDs the claim names: its entities, then IDs in its value."""
    ids = [*claim.entities.ghsa, *claim.entities.cve]
    if isinstance(claim, IdentifierClaim):
        ids += [claim.value.id, *claim.value.aliases]
    return list(dict.fromkeys(ids))


# --- what the extractor returns ----------------------------------------------------------------


class ExtractedValue(Strict):
    """Flat union of every typed value's fields; code keeps only the fields of the claim's type."""

    fixed: str | None = None
    affected: str | None = Field(
        default=None, description="Version range in comparator form, e.g. '>= 2.0.0, < 3.8.0'."
    )
    no_fix: bool | None = None
    package: str | None = None
    label: str | None = None
    cvss_version: str | None = None
    score: float | None = None
    vector: str | None = None
    cwe: list[str] | None = None
    kind: str | None = Field(
        default=None, description="Date kind: published, updated, fixed, disclosed or reported."
    )
    date: str | None = Field(default=None, description="YYYY, YYYY-MM or YYYY-MM-DD.")
    id: str | None = None
    product: str | None = None
    vendor: str | None = None
    aliases: list[str] | None = None
    framework: str | None = Field(default=None, description="Taxonomy framework: atlas or owasp.")
    name: str | None = None
    tactic: str | None = None


class ExtractedEntities(Strict):
    ghsa: list[str] = Field(default_factory=list[str])
    cve: list[str] = Field(default_factory=list[str])
    atlas: list[str] = Field(default_factory=list[str])
    owasp: list[str] = Field(default_factory=list[str])
    urls: list[str] = Field(default_factory=list[str])


class ExtractedClaim(Strict):
    first_line: int = Field(description="Line number shown before the first line of the quote.")
    last_line: int = Field(description="Line number shown before the last line of the quote.")
    quote: str = Field(description="Exact characters copied from those lines, without prefixes.")
    text: str = Field(description="The claim as one self-contained sentence.")
    type: str = Field(description="One of: " + ", ".join(CLAIM_TYPES) + ".")
    entities: ExtractedEntities = Field(default_factory=ExtractedEntities)
    cited_urls: list[str] = Field(default_factory=list[str])
    value: ExtractedValue | None = None


class ExtractionResult(Strict):
    """Atomic, checkable claims from one note section."""

    claims: list[ExtractedClaim] = Field(default_factory=list[ExtractedClaim])


class RejectedClaim(Strict):
    note_path: str
    lines: tuple[int, int] | None = None
    quote: str = ""
    type: str = ""
    reason: Literal[
        "schema",
        "unknown_type",
        "bad_lines",
        "quote_not_found",
        "bad_entity_id",
        "entity_not_in_note",
        "url_not_in_note",
        "bad_value",
    ]
    detail: str = ""
