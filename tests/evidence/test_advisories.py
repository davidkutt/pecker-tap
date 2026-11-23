import hashlib
import json
from pathlib import Path

import pytest

from pecker_tap.config import HttpConfig, RateLimit
from pecker_tap.evidence.advisories import (
    lookup_advisory,
    parse_cve_org,
    parse_github,
    parse_nvd,
    repo_hints,
)
from pecker_tap.evidence.http import Fetched, HttpClient, ResponseStore

GHSA = "GHSA-0000-0000-0001"
CPE = "cpe:2.3:a:tap-fixture-acme:acme_sdk:*:*:*:*:*:node.js:*:*"
CVE = "CVE-2099-0001"
GLOBAL = {
    "ghsa_id": GHSA,
    "cve_id": CVE,
    "identifiers": [{"type": "GHSA", "value": GHSA}, {"type": "CVE", "value": CVE}],
    "severity": "moderate",
    "repository_advisory_url": f"https://api.github.com/repos/tap-fixture-acme/sdk/security-advisories/{GHSA}",
    "source_code_location": "https://github.com/tap-fixture-acme/sdk",
    "cvss_severities": {
        "cvss_v3": {"vector_string": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N", "score": 6.5},
        "cvss_v4": {"vector_string": None, "score": 0.0},
    },
    "cwes": [{"cwe_id": "CWE-22", "name": "Path traversal"}],
    "vulnerabilities": [
        {
            "package": {"ecosystem": "npm", "name": "acme-sdk"},
            "vulnerable_version_range": "< 3.8.0",
            "first_patched_version": "3.8.0",
        },
        {
            "package": {"ecosystem": "npm", "name": "acme-cli"},
            "vulnerable_version_range": "<= 1.0.0",
            "first_patched_version": None,
        },
    ],
    "published_at": "2099-01-15T10:00:00Z",
    "updated_at": "2099-02-01T08:00:00Z",
    "withdrawn_at": None,
}


def test_github_global_record() -> None:
    record = parse_github(GLOBAL, "https://api.github.com/advisories/x")
    assert record.source == "github_global"
    assert record.ids == (GHSA,)
    assert record.aliases == (CVE,)
    assert record.severity_label == "medium"  # moderate is GitHub's word for medium
    assert [(c.version, c.score) for c in record.cvss] == [("3.1", 6.5)]  # empty v4 skipped
    assert record.cwes == ("CWE-22",)
    assert [(p.name, p.patched, p.patched_stated) for p in record.packages] == [
        ("acme-sdk", ("3.8.0",), True),
        ("acme-cli", (), True),  # null first_patched_version: GitHub says there is no fix
    ]
    assert record.repository == "tap-fixture-acme/sdk"
    assert record.published == "2099-01-15T10:00:00Z"


def test_github_repository_record_with_unfilled_patched_versions() -> None:
    data = {
        **GLOBAL,
        "vulnerabilities": [
            {"package": {"name": "acme-sdk"}, "patched_versions": "3.8.0, 2.9.4"},
            {"package": {"name": "acme-cli"}, "patched_versions": None},
        ],
    }
    record = parse_github(data, "u", repository_advisory=True)
    assert record.source == "github_repo"
    assert [(p.patched, p.patched_stated) for p in record.packages] == [
        (("3.8.0", "2.9.4"), True),
        ((), False),  # unfilled says nothing
    ]


def test_parsers_tolerate_junk() -> None:
    assert parse_github({"vulnerabilities": "nope", "cwes": [1, None]}, "u").packages == ()
    assert parse_cve_org([], "u").ids == ()
    assert parse_nvd({"vulnerabilities": []}, "u") is None
    assert parse_nvd("junk", "u") is None


def test_cve_org_record() -> None:
    data = {
        "cveMetadata": {"cveId": CVE, "state": "PUBLISHED", "datePublished": "2099-01-15T12:00:00"},
        "containers": {
            "cna": {
                "affected": [
                    {
                        "vendor": "tap-fixture-acme",
                        "product": "acme-sdk",
                        "collectionURL": "https://www.npmjs.com",
                        "versions": [{"version": "< 3.8.0", "status": "affected"}],
                    },
                    {
                        "vendor": "tap-fixture-acme",
                        "product": "acme-agent",
                        "versions": [
                            {"version": "2.0", "lessThan": "2.4", "status": "affected"},
                            {"version": "2.4", "status": "unaffected"},
                        ],
                    },
                ],
                "metrics": [
                    {"cvssV3_1": {"version": "3.1", "baseScore": 6.5, "baseSeverity": "MEDIUM"}}
                ],
                "problemTypes": [{"descriptions": [{"cweId": "CWE-22", "type": "CWE"}]}],
                "references": [
                    {"url": f"https://github.com/tap-fixture-acme/sdk/security/advisories/{GHSA}"}
                ],
            },
            "adp": [{"metrics": [{"cvssV3_1": {"baseScore": 9.9}}]}],
        },
    }
    record = parse_cve_org(data, "u")
    assert record.ids == (CVE,)
    assert record.aliases == (GHSA,)
    assert [(p.vendor, p.product) for p in record.products] == [
        ("tap-fixture-acme", "acme-sdk"),
        ("tap-fixture-acme", "acme-agent"),
    ]
    assert [(p.ecosystem, p.vulnerable_range, p.patched) for p in record.packages] == [
        ("npm", "< 3.8.0", ("3.8.0",)),
        (None, ">= 2.0, < 2.4", ("2.4",)),
    ]
    assert [(c.score, c.label) for c in record.cvss] == [(6.5, "medium")]  # ADP not used
    assert record.cwes == ("CWE-22",)


def test_nvd_record_uses_primary_metrics_only() -> None:
    data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": CVE,
                    "published": "2099-01-15T12:15:00.000",
                    "metrics": {
                        "cvssMetricV31": [
                            {"type": "Primary", "cvssData": {"version": "3.1", "baseScore": 7.1,
                                                             "baseSeverity": "HIGH"}},
                            {"type": "Secondary", "cvssData": {"version": "3.1", "baseScore": 6.5}},
                        ]
                    },
                    "weaknesses": [
                        {"type": "Primary", "description": [{"value": "NVD-CWE-Other"}]},
                        {"type": "Secondary", "description": [{"value": "CWE-23"}]},
                    ],
                    "configurations": [
                        {"nodes": [{"cpeMatch": [
                            {"vulnerable": True, "versionEndExcluding": "3.8.0",
                             "criteria": CPE},
                            {"vulnerable": False, "criteria": "cpe:2.3:o:x:y:*"},
                        ]}]}
                    ],
                }
            }
        ]
    }  # fmt: skip
    record = parse_nvd(data, "u")
    assert record is not None
    assert [(c.score, c.label) for c in record.cvss] == [(7.1, "high")]
    assert record.cwes == ()  # NVD-CWE-Other is not a CWE; secondary weaknesses are skipped
    assert [(p.vendor, p.product) for p in record.products] == [("tap-fixture-acme", "acme sdk")]
    assert [(p.vulnerable_range, p.patched) for p in record.packages] == [("< 3.8.0", ("3.8.0",))]


def test_repo_hints_come_from_advisory_urls_for_the_same_ghsa() -> None:
    text = (
        f"See https://github.com/tap-fixture-acme/sdk/security/advisories/{GHSA.lower()} and "
        "https://github.com/tap-fixture-other/x/security/advisories/GHSA-0000-0000-0010."
    )
    assert repo_hints(text, GHSA) == ["tap-fixture-acme/sdk"]


def _store(root: Path, url: str, status: int, data: object) -> None:
    body = json.dumps(data).encode()
    ResponseStore(root).put(
        Fetched(url, url, status, {}, body, "t", hashlib.sha256(body).hexdigest())
    )


@pytest.fixture
def offline(tmp_path: Path) -> HttpClient:
    sources = tmp_path / "sources"
    _store(sources, f"https://api.github.com/advisories/{GHSA}", 200, GLOBAL)
    _store(sources, GLOBAL["repository_advisory_url"], 404, {"message": "Not Found"})  # type: ignore[arg-type]
    _store(sources, f"https://cveawg.mitre.org/api/cve/{CVE}", 503, {})
    return HttpClient(
        HttpConfig(user_agent="t"),
        lambda _h: RateLimit(requests=10, per_seconds=1),
        online=False,
        sources=sources,
    )


async def test_lookup_reports_each_failing_source_with_a_reason(offline: HttpClient) -> None:
    lookup = await lookup_advisory(GHSA, ["tap-fixture-acme/sdk"], offline)
    assert [r.source for r in lookup.records] == ["github_global"]
    assert [(f.source, f.reason) for f in lookup.failures] == [
        ("github_repo", "not_found"),  # hint and record name the same URL: fetched once
        ("cve_org", "unreachable"),
        ("nvd", "no_source"),
    ]


async def test_cve_lookup_reuses_a_known_ghsa_lookup(offline: HttpClient) -> None:
    ghsa_lookup = await lookup_advisory(GHSA, [], offline)
    cve_lookup = await lookup_advisory(CVE, [], offline, known=[ghsa_lookup])
    assert cve_lookup.records == ghsa_lookup.records
    assert cve_lookup.key == CVE
