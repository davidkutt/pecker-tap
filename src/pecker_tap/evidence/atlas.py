"""MITRE ATLAS from the YAML of a pinned release (V1 brief, deliverable 6).

The file is fetched once per run through the HTTP client (so it lands in the run cache), its
sha256 and ``collection.version`` are checked against the pin in ``config/defaults.toml``, and it
is parsed with ``yaml.safe_load``. A file that fails either check is never used.

The index doesn't depend on the YAML layout: every mapping with an ATLAS ``id`` and a ``name`` is
an entry; a technique's tactics come from its ``tactics`` list (sub-techniques inherit their
parent's); a case study links every technique ID it mentions anywhere inside it.

**Offline pin override (ADR 0002).** A ``--sources`` folder may carry ``pins.toml`` with an
``[atlas]`` table (``release``, ``url``, ``sha256``, ``collection_version``). Offline runs from
that folder use it instead of the configured pin, and the run says so. The synthetic fixtures use
it to serve a small synthetic release; ``--online`` runs ignore it.
"""

from __future__ import annotations

import asyncio
import tomllib
from collections.abc import Iterator, Mapping
from typing import cast

import yaml
from pydantic import ValidationError

from pecker_tap.claims.patterns import canonical, find_ids, matches
from pecker_tap.config import AtlasPin
from pecker_tap.evidence.http import Fetched, HttpClient
from pecker_tap.evidence.records import AtlasEntry, AtlasResult, Lookup, SourceFailure

PINS_FILE = "pins.toml"


class AtlasError(RuntimeError):
    def __init__(self, reason: str, detail: str) -> None:
        super().__init__(detail)
        self.reason = reason
        self.detail = detail


def _walk(node: object) -> Iterator[Mapping[str, object]]:
    if isinstance(node, Mapping):
        mapping = cast("Mapping[str, object]", node)
        yield mapping
        for value in mapping.values():
            yield from _walk(value)
    elif isinstance(node, list):
        for item in cast("list[object]", node):
            yield from _walk(item)


def _strings(node: object) -> Iterator[str]:
    if isinstance(node, str):
        yield node
    elif isinstance(node, Mapping):
        for value in cast("Mapping[str, object]", node).values():
            yield from _strings(value)
    elif isinstance(node, list):
        for item in cast("list[object]", node):
            yield from _strings(item)


def _id_list(value: object) -> list[str]:
    items = cast("list[object]", value) if isinstance(value, list) else [value]
    return [canonical("atlas", i) for i in items if isinstance(i, str) and matches("atlas", i)]


def build_index(data: object) -> dict[str, AtlasEntry]:
    objects: dict[str, Mapping[str, object]] = {}
    for mapping in _walk(data):
        raw_id, name = mapping.get("id"), mapping.get("name")
        if isinstance(raw_id, str) and matches("atlas", raw_id) and isinstance(name, str):
            objects.setdefault(canonical("atlas", raw_id), mapping)
    names = {key: str(obj["name"]) for key, obj in objects.items()}
    case_studies: dict[str, list[str]] = {}
    for key, obj in objects.items():
        if key.startswith("AML.CS"):
            mentioned = {i for text in _strings(obj) for i in find_ids("atlas", text)}
            for technique in sorted(mentioned - {key}):
                case_studies.setdefault(technique, []).append(key)

    def tactics_of(key: str, depth: int = 0) -> list[str]:
        obj = objects.get(key, {})
        own = _id_list(obj.get("tactics"))
        parent = obj.get("subtechnique-of")
        if not own and isinstance(parent, str) and depth < 3:
            return tactics_of(canonical("atlas", parent), depth + 1)
        return own

    index: dict[str, AtlasEntry] = {}
    for key, obj in objects.items():
        tactics = tactics_of(key)
        index[key] = AtlasEntry(
            id=key,
            name=names[key],
            object_type=str(obj.get("object-type") or ""),
            tactics=tuple(tactics),
            tactic_names=tuple(names[t] for t in tactics if t in names),
            case_studies=tuple(case_studies.get(key, ())),
        )
    return index


def check_release(body: bytes, sha256: str, pin: AtlasPin) -> object:
    """Parse the release after checking its hash and collection version."""
    if sha256 != pin.sha256:
        msg = f"sha256 of the downloaded file does not match the pin for {pin.release}"
        raise AtlasError("bad_data", msg)
    try:
        data: object = yaml.safe_load(body.decode("utf-8"))
    except (UnicodeDecodeError, yaml.YAMLError):
        raise AtlasError("bad_data", "the ATLAS file is not valid YAML") from None
    if not isinstance(data, Mapping):
        raise AtlasError("bad_data", "the ATLAS file is not a mapping")
    release = cast("Mapping[str, object]", data)
    collection = release.get("collection")
    version = (
        cast("Mapping[str, object]", collection).get("version")
        if isinstance(collection, Mapping)
        else None
    )
    if str(version) != pin.collection_version:
        msg = f"collection version is not {pin.collection_version}"
        raise AtlasError("bad_data", msg)
    return release


def sources_pin(http: HttpClient) -> AtlasPin | None:
    """The ``[atlas]`` pin of the ``--sources`` folder, for offline runs only."""
    folder = http.sources_dir
    if http.online or folder is None or not (folder / PINS_FILE).is_file():
        return None
    try:
        data = tomllib.loads((folder / PINS_FILE).read_text(encoding="utf-8"))
        return AtlasPin.model_validate(data.get("atlas"))
    except (OSError, tomllib.TOMLDecodeError, ValidationError):
        return None


class AtlasSource:
    """Loads the pinned release once per run and answers lookups by ID."""

    def __init__(self, http: HttpClient, pin: AtlasPin, size_cap: int) -> None:
        override = sources_pin(http)
        self.pin = override or pin
        self.synthetic = override is not None
        self.http = http
        self.size_cap = size_cap
        self._index: dict[str, AtlasEntry] | None = None
        self._error: AtlasError | None = None
        self._lock = asyncio.Lock()

    async def _load(self) -> dict[str, AtlasEntry]:
        async with self._lock:
            if self._index is not None:
                return self._index
            if self._error is not None:
                raise self._error
            result = await self.http.get(
                self.pin.url, accept="application/yaml, text/plain", size_cap=self.size_cap
            )
            try:
                if not isinstance(result, Fetched):
                    reason = "no_source" if result.kind == "no_source" else "unreachable"
                    raise AtlasError(reason, result.detail or result.kind)
                if result.status != 200:
                    raise AtlasError("unreachable", f"HTTP {result.status}")
                self._index = build_index(check_release(result.body, result.sha256, self.pin))
            except AtlasError as exc:
                self._error = exc
                raise
            return self._index

    async def lookup(self, key: str) -> Lookup:
        try:
            index = await self._load()
        except AtlasError as exc:
            failure = SourceFailure(
                source="atlas",
                url=self.pin.url,
                reason=exc.reason,  # type: ignore[arg-type]
                detail=exc.detail,
            )
            return Lookup(key=key, failures=(failure,))
        return Lookup(
            key=key,
            atlas=AtlasResult(
                release=self.pin.release,
                url=self.pin.url,
                entry=index.get(key),
                synthetic_pin=self.synthetic,
            ),
        )
