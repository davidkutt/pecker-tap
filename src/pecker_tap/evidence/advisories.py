"""Advisory sources: GitHub global and repository advisories, CVE.org and NVD (V1 brief, 6).

Parsers turn one API response into an ``AdvisoryRecord`` and never raise on missing or odd fields:
whatever isn't there stays empty. ``lookup_advisory`` fetches everything for one CVE or GHSA ID
through the HTTP client and reports each source that failed, with a reason.

Notes on what the sources say:

- GitHub's global record states ``first_patched_version`` explicitly: ``null`` means no fix. A
  repository advisory's ``patched_versions`` may simply be unfilled, so ``null`` there says nothing.
- CVE.org records are read from the CNA container; an ADP container's CVSS is used only when the
  CNA gives none. NVD records are read from NVD's own (``Primary``) metrics and weaknesses.
- A 404 is not evidence that an ID doesn't exist (reserved CVEs, unpublished repository
  advisories): it is reported as ``not_found`` and the comparison treats it as no source.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping, Sequence
from typing import TypeIs, cast

from pecker_tap.claims.patterns import GITHUB_ADVISORY_URL, canonical, find_ids, matches
from pecker_tap.evidence.http import Fetched, FetchError, FetchResult, HttpClient
from pecker_tap.evidence.records import (
    AdvisoryRecord,
    AffectedPackage,
    Cvss,
    FailureReason,
    Lookup,
    Product,
    SourceFailure,
)

GITHUB_API = "https://api.github.com"
GITHUB_ACCEPT = "application/vnd.github+json"
CVE_ORG_API = "https://cveawg.mitre.org/api/cve/"
NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId="
MAX_GHSA_PER_CVE = 3

_VECTOR_VERSION = re.compile(r"^CVSS:(\d\.\d)/")
_UPPER_BOUND = re.compile(r"<\s*=?\s*v?([0-9][^\s,]*)")
_EXCLUSIVE_UPPER = re.compile(r"(?<![<>=])<\s*v?([0-9][^\s,]*)")
_REPO_URL = re.compile(r"https://github\.com/([A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100})")
_ECOSYSTEMS = {
    "npmjs": "npm",
    "pypi": "pip",
    "crates.io": "rust",
    "golang": "go",
    "maven": "maven",
    "rubygems": "rubygems",
    "nuget": "nuget",
    "packagist": "composer",
}


def _map(value: object) -> Mapping[str, object]:
    return cast("Mapping[str, object]", value) if isinstance(value, Mapping) else {}


def _is_map(value: object) -> TypeIs[Mapping[str, object]]:
    return isinstance(value, Mapping)


def _list(value: object) -> list[object]:
    return cast("list[object]", value) if isinstance(value, list) else []


def _str(value: object) -> str | None:
    if isinstance(value, str) and value.strip():
        return value.strip()
    if isinstance(value, int | float) and not isinstance(value, bool):
        return str(value)
    return None


def _float(value: object) -> float | None:
    return float(value) if isinstance(value, int | float) and not isinstance(value, bool) else None


def _label(value: object) -> str | None:
    text = _str(value)
    if text is None:
        return None
    lowered = text.lower()
    return "medium" if lowered == "moderate" else lowered


def _vector_version(vector: str | None, fallback: str) -> str:
    match = _VECTOR_VERSION.match(vector or "")
    return match.group(1) if match else fallback


def _cwe_list(values: Iterable[object]) -> tuple[str, ...]:
    found: list[str] = []
    for value in values:
        text = _str(value)
        if text and matches("cwe", text):
            found.append(canonical("cwe", text))
    return tuple(dict.fromkeys(found))


# --- GitHub ------------------------------------------------------------------------------------


def _github_cvss(data: Mapping[str, object], base: str) -> tuple[Cvss, ...]:
    entries: list[Cvss] = []
    severities = _map(data.get("cvss_severities"))
    for key, fallback in (("cvss_v4", "4.0"), ("cvss_v3", "3.1")):
        item = _map(severities.get(key))
        vector, score = _str(item.get("vector_string")), _float(item.get("score"))
        if vector or score:
            entries.append(
                Cvss(
                    version=_vector_version(vector, fallback),
                    score=score,
                    vector=vector,
                    field=f"{base}cvss_severities.{key}",
                )
            )
    if not entries:
        item = _map(data.get("cvss"))
        vector, score = _str(item.get("vector_string")), _float(item.get("score"))
        if vector or score:
            entries.append(
                Cvss(
                    version=_vector_version(vector, "3.1"),
                    score=score,
                    vector=vector,
                    field=f"{base}cvss",
                )
            )
    return tuple(entries)


def _repo_from_url(value: object) -> str | None:
    match = _REPO_URL.match(_str(value) or "")
    return match.group(1) if match else None


def parse_github(data: object, url: str, *, repository_advisory: bool = False) -> AdvisoryRecord:
    """A global (``/advisories/{ghsa}``) or repository advisory record."""
    item = _map(data)
    ghsa = _str(item.get("ghsa_id"))
    cve = _str(item.get("cve_id"))
    identifiers = [_str(_map(i).get("value")) for i in _list(item.get("identifiers"))]
    aliases = [i for i in [cve, *identifiers] if i and i != ghsa]
    packages: list[AffectedPackage] = []
    for index, raw in enumerate(_list(item.get("vulnerabilities"))):
        vuln = _map(raw)
        package = _map(vuln.get("package"))
        name = _str(package.get("name"))
        if not name:
            continue
        if repository_advisory:
            patched_raw = _str(vuln.get("patched_versions"))
            patched = tuple(p.strip() for p in (patched_raw or "").split(",") if p.strip())
            stated = bool(patched)
            field = f"vulnerabilities[{index}].patched_versions"
        else:
            first = vuln.get("first_patched_version")
            first_text = _str(_map(first).get("identifier")) if _is_map(first) else _str(first)
            patched = (first_text,) if first_text else ()
            stated = True
            field = f"vulnerabilities[{index}].first_patched_version"
        packages.append(
            AffectedPackage(
                ecosystem=_str(package.get("ecosystem")),
                name=name,
                vulnerable_range=_str(vuln.get("vulnerable_version_range")),
                patched=patched,
                patched_stated=stated,
                field=field,
            )
        )
    cwes = _cwe_list(_map(c).get("cwe_id") for c in _list(item.get("cwes")))
    if not cwes:
        cwes = _cwe_list(_list(item.get("cwe_ids")))
    repository = _repo_from_url(item.get("source_code_location")) or _repo_from_url(
        item.get("html_url")
    )
    return AdvisoryRecord(
        source="github_repo" if repository_advisory else "github_global",
        url=url,
        ids=tuple(canonical("ghsa", ghsa) for ghsa in [ghsa] if ghsa and matches("ghsa", ghsa)),
        aliases=tuple(
            dict.fromkeys(
                canonical("cve", a) if matches("cve", a) else canonical("ghsa", a)
                for a in aliases
                if matches("cve", a) or matches("ghsa", a)
            )
        ),
        severity_label=_label(item.get("severity")),
        severity_field="severity" if _label(item.get("severity")) else None,
        cvss=_github_cvss(item, ""),
        cwes=cwes,
        cwe_field="cwes" if cwes else None,
        packages=tuple(packages),
        products=tuple(
            Product(product=p.name, vendor=None, field=f"vulnerabilities[{i}].package.name")
            for i, p in enumerate(packages)
        ),
        published=_str(item.get("published_at")),
        published_field="published_at" if _str(item.get("published_at")) else None,
        updated=_str(item.get("updated_at")),
        updated_field="updated_at" if _str(item.get("updated_at")) else None,
        withdrawn=_str(item.get("withdrawn_at")) is not None,
        repository=repository,
        repository_advisory_url=_str(item.get("repository_advisory_url")),
    )


# --- CVE.org -----------------------------------------------------------------------------------


def _ecosystem(collection_url: str | None) -> str | None:
    for marker, name in _ECOSYSTEMS.items():
        if collection_url and marker in collection_url:
            return name
    return None


def _cve_versions(versions: Sequence[object]) -> tuple[str | None, tuple[str, ...]]:
    """An affected range and the fixed versions it implies (exclusive upper bounds)."""
    ranges: list[str] = []
    fixed: list[str] = []
    for raw in versions:
        entry = _map(raw)
        if (_str(entry.get("status")) or "").lower() != "affected":
            continue
        version = _str(entry.get("version")) or ""
        less_than, less_equal = _str(entry.get("lessThan")), _str(entry.get("lessThanOrEqual"))
        lower = f">= {version}, " if version not in {"", "0", "*", "n/a"} else ""
        if less_than and less_than != "*":
            ranges.append(f"{lower}< {less_than}")
            fixed.append(less_than)
        elif less_equal and less_equal != "*":
            ranges.append(f"{lower}<= {less_equal}")
        elif version:
            ranges.append(version)
            fixed += _EXCLUSIVE_UPPER.findall(version)
    return ("; ".join(ranges) or None), tuple(dict.fromkeys(fixed))


def _cve_metrics(metrics: Sequence[object], base: str) -> list[Cvss]:
    entries: list[Cvss] = []
    for index, raw in enumerate(metrics):
        metric = _map(raw)
        for key, version in (("cvssV4_0", "4.0"), ("cvssV3_1", "3.1"), ("cvssV3_0", "3.0"),
                             ("cvssV2_0", "2.0")):  # fmt: skip
            data = _map(metric.get(key))
            if data:
                entries.append(
                    Cvss(
                        version=_str(data.get("version")) or version,
                        score=_float(data.get("baseScore")),
                        vector=_str(data.get("vectorString")),
                        label=_label(data.get("baseSeverity")),
                        field=f"{base}metrics[{index}].{key}",
                    )
                )
    return entries


def parse_cve_org(data: object, url: str) -> AdvisoryRecord:
    record = _map(data)
    meta = _map(record.get("cveMetadata"))
    containers = _map(record.get("containers"))
    cna = _map(containers.get("cna"))
    cve_id = _str(meta.get("cveId"))
    products: list[Product] = []
    packages: list[AffectedPackage] = []
    for index, raw in enumerate(_list(cna.get("affected"))):
        affected = _map(raw)
        product = _str(affected.get("product")) or _str(affected.get("packageName"))
        if not product:
            continue
        field = f"containers.cna.affected[{index}]"
        products.append(Product(vendor=_str(affected.get("vendor")), product=product, field=field))
        vulnerable_range, fixed = _cve_versions(_list(affected.get("versions")))
        packages.append(
            AffectedPackage(
                ecosystem=_ecosystem(_str(affected.get("collectionURL"))),
                name=_str(affected.get("packageName")) or product,
                vulnerable_range=vulnerable_range,
                patched=fixed,
                patched_stated=bool(fixed),
                field=f"{field}.versions",
            )
        )
    cvss = _cve_metrics(_list(cna.get("metrics")), "containers.cna.")
    if not cvss:
        for index, adp in enumerate(_list(containers.get("adp"))):
            cvss += _cve_metrics(_list(_map(adp).get("metrics")), f"containers.adp[{index}].")
    cwes = _cwe_list(
        _map(description).get("cweId")
        for problem in _list(cna.get("problemTypes"))
        for description in _list(_map(problem).get("descriptions"))
    )
    references = " ".join(_str(_map(r).get("url")) or "" for r in _list(cna.get("references")))
    return AdvisoryRecord(
        source="cve_org",
        url=url,
        ids=(canonical("cve", cve_id),) if cve_id and matches("cve", cve_id) else (),
        aliases=tuple(find_ids("ghsa", references)),
        cvss=tuple(cvss),
        cwes=cwes,
        cwe_field="containers.cna.problemTypes" if cwes else None,
        packages=tuple(packages),
        products=tuple(products),
        published=_str(meta.get("datePublished")),
        published_field="cveMetadata.datePublished" if meta.get("datePublished") else None,
        updated=_str(meta.get("dateUpdated")),
        updated_field="cveMetadata.dateUpdated" if meta.get("dateUpdated") else None,
        withdrawn=(_str(meta.get("state")) or "").upper() == "REJECTED",
    )


# --- NVD ---------------------------------------------------------------------------------------


def _nvd_range(match: Mapping[str, object]) -> tuple[str | None, str | None]:
    parts: list[str] = []
    for key, op in (("versionStartIncluding", ">="), ("versionStartExcluding", ">")):
        if _str(match.get(key)):
            parts.append(f"{op} {_str(match.get(key))}")
    end_excl = _str(match.get("versionEndExcluding"))
    end_incl = _str(match.get("versionEndIncluding"))
    if end_excl:
        parts.append(f"< {end_excl}")
    elif end_incl:
        parts.append(f"<= {end_incl}")
    return (", ".join(parts) or None), end_excl


def parse_nvd(data: object, url: str) -> AdvisoryRecord | None:
    """The first vulnerability of an NVD response; ``None`` if the response holds none."""
    items = _list(_map(data).get("vulnerabilities"))
    if not items:
        return None
    cve = _map(_map(items[0]).get("cve"))
    cve_id = _str(cve.get("id"))
    metrics = _map(cve.get("metrics"))
    cvss: list[Cvss] = []
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for index, raw in enumerate(_list(metrics.get(key))):
            metric = _map(raw)
            if (_str(metric.get("type")) or "").lower() != "primary":
                continue
            data_ = _map(metric.get("cvssData"))
            cvss.append(
                Cvss(
                    version=_str(data_.get("version")) or key[-2:],
                    score=_float(data_.get("baseScore")),
                    vector=_str(data_.get("vectorString")),
                    label=_label(data_.get("baseSeverity") or metric.get("baseSeverity")),
                    field=f"metrics.{key}[{index}]",
                )
            )
    cwes = _cwe_list(
        _map(description).get("value")
        for weakness in _list(cve.get("weaknesses"))
        if (_str(_map(weakness).get("type")) or "").lower() == "primary"
        for description in _list(_map(weakness).get("description"))
    )
    products: list[Product] = []
    packages: list[AffectedPackage] = []
    for c_index, config in enumerate(_list(cve.get("configurations"))):
        for n_index, node in enumerate(_list(_map(config).get("nodes"))):
            for m_index, raw in enumerate(_list(_map(node).get("cpeMatch"))):
                match = _map(raw)
                parts = (_str(match.get("criteria")) or "").split(":")
                if match.get("vulnerable") is not True or len(parts) < 5:
                    continue
                field = f"configurations[{c_index}].nodes[{n_index}].cpeMatch[{m_index}]"
                vendor, product = parts[3].replace("_", " "), parts[4].replace("_", " ")
                products.append(Product(vendor=vendor, product=product, field=field))
                vulnerable_range, fixed = _nvd_range(match)
                packages.append(
                    AffectedPackage(
                        name=parts[4],
                        vulnerable_range=vulnerable_range,
                        patched=(fixed,) if fixed else (),
                        patched_stated=bool(fixed),
                        field=field,
                    )
                )
    return AdvisoryRecord(
        source="nvd",
        url=url,
        ids=(canonical("cve", cve_id),) if cve_id and matches("cve", cve_id) else (),
        cvss=tuple(cvss),
        cwes=cwes,
        cwe_field="weaknesses" if cwes else None,
        packages=tuple(packages),
        products=tuple(products),
        published=_str(cve.get("published")),
        published_field="published" if cve.get("published") else None,
        updated=_str(cve.get("lastModified")),
        updated_field="lastModified" if cve.get("lastModified") else None,
        withdrawn=(_str(cve.get("vulnStatus")) or "").lower() == "rejected",
    )


# --- lookups -----------------------------------------------------------------------------------


def repo_hints(text: str, ghsa: str) -> list[str]:
    """``owner/repo`` of every GitHub repository advisory URL for ``ghsa`` in ``text``."""
    return list(
        dict.fromkeys(
            f"{m.group(1)}/{m.group(2)}"
            for m in GITHUB_ADVISORY_URL.finditer(text)
            if canonical("ghsa", m.group(3)) == ghsa
        )
    )


def _failure(source: str, result: FetchResult) -> SourceFailure | None:
    if isinstance(result, FetchError):
        reason: FailureReason = (
            "no_source"
            if result.kind == "no_source"
            else "bad_data"
            if result.kind == "bad_record"
            else "blocked"
            if result.kind == "blocked"
            else "unreachable"
        )
        return SourceFailure(source=source, url=result.url, reason=reason, detail=result.detail)
    if result.status == 200:
        return None
    reason = "not_found" if result.status == 404 else "unreachable"
    return SourceFailure(
        source=source, url=result.url, reason=reason, detail=f"HTTP {result.status}"
    )


def _json(result: Fetched, source: str) -> tuple[object, SourceFailure | None]:
    try:
        return json.loads(result.body), None
    except ValueError:
        return None, SourceFailure(
            source=source, url=result.url, reason="bad_data", detail="response is not JSON"
        )


class _Collector:
    def __init__(self, http: HttpClient) -> None:
        self.http = http
        self.records: list[AdvisoryRecord] = []
        self.failures: list[SourceFailure] = []
        self.seen: set[str] = set()

    async def fetch_json(self, source: str, url: str, accept: str) -> object | None:
        if url in self.seen:
            return None
        self.seen.add(url)
        result = await self.http.get(url, accept=accept)
        failure = _failure(source, result)
        if failure is not None or not isinstance(result, Fetched):
            if failure is not None:
                self.failures.append(failure)
            return None
        data, problem = _json(result, source)
        if problem is not None:
            self.failures.append(problem)
        return data

    async def github_repo(self, url: str) -> None:
        data = await self.fetch_json("github_repo", url, GITHUB_ACCEPT)
        if _is_map(data):
            self.records.append(parse_github(data, url, repository_advisory=True))

    async def cve(self, cve_id: str) -> None:
        url = CVE_ORG_API + cve_id
        data = await self.fetch_json("cve_org", url, "application/json")
        if _is_map(data):
            self.records.append(parse_cve_org(data, url))
        url = NVD_API + cve_id
        data = await self.fetch_json("nvd", url, "application/json")
        if _is_map(data):
            record = parse_nvd(data, url)
            if record is None:
                self.failures.append(
                    SourceFailure(source="nvd", url=url, reason="not_found", detail="no results")
                )
            else:
                self.records.append(record)


def _repo_advisory_url(repo: str, ghsa: str) -> str:
    return f"{GITHUB_API}/repos/{repo}/security-advisories/{ghsa}"


async def lookup_advisory(
    key: str, hints: Sequence[str], http: HttpClient, known: Sequence[Lookup] = ()
) -> Lookup:
    """Every structured record for one CVE or GHSA ID. ``hints``: ``owner/repo`` from the note.

    A CVE that a GHSA lookup in ``known`` already lists as an alias reuses that lookup (its
    CVE.org and NVD records included) instead of searching GitHub again.
    """
    if matches("cve", key):
        covering = [
            lookup
            for lookup in known
            if any(key in record.aliases or key in record.ids for record in lookup.records)
        ]
        if covering:
            records = {r.url: r for lookup in covering for r in lookup.records}
            failures = {(f.source, f.url): f for lookup in covering for f in lookup.failures}
            return Lookup(
                key=key, records=tuple(records.values()), failures=tuple(failures.values())
            )
    collector = _Collector(http)
    cves: list[str] = []
    repo_urls: list[str] = []
    if matches("ghsa", key):
        url = f"{GITHUB_API}/advisories/{key}"
        data = await collector.fetch_json("github_global", url, GITHUB_ACCEPT)
        if _is_map(data):
            record = parse_github(data, url)
            collector.records.append(record)
            cves += [a for a in record.aliases if a.startswith("CVE-")]
            if record.repository_advisory_url:
                repo_urls.append(record.repository_advisory_url)
        repo_urls = [_repo_advisory_url(repo, key) for repo in hints] + repo_urls
    elif matches("cve", key):
        cves.append(key)
        url = f"{GITHUB_API}/advisories?cve_id={key}"
        data = await collector.fetch_json("github_global", url, GITHUB_ACCEPT)
        for item in _list(data)[:MAX_GHSA_PER_CVE]:
            ghsa = _str(_map(item).get("ghsa_id")) or ""
            record = parse_github(item, f"{GITHUB_API}/advisories/{ghsa}" if ghsa else url)
            collector.records.append(record)
            if record.repository_advisory_url:
                repo_urls.append(record.repository_advisory_url)
    for repo_url in dict.fromkeys(repo_urls):
        await collector.github_repo(repo_url)
    for cve_id in dict.fromkeys(cves):
        await collector.cve(cve_id)
    return Lookup(key=key, records=tuple(collector.records), failures=tuple(collector.failures))
