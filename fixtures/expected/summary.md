# pecker-tap summary

- Run: `<run_id>` (finished)
- Model: `fake:fixtures`
- Notes: `fixtures/notes` at `<notes_sha>`, 7 notes
- Checked on: <checked_on>
- Evidence: offline, sources `fixtures/http`
- ATLAS: `v2099.01-synthetic` (synthetic pin from --sources)
- Cost: 0.0000 USD for 9 model calls (0.000000 USD per claim; cap 0.50 USD)

## Counts

| Status | Entries |
| --- | ---: |
| verified | 10 |
| contradicted | 4 |
| new_finding | 5 |
| unclear | 9 |

23 claims, 0 rejected claims, 0 notes that failed to parse, 0 sections whose model call failed.

## Contradictions

- `c-0001` `advisories/brambleport-auth-bypass.md:8`: `The brambleport authentication bypass is fixed in 2.4.1.` Correct: `{"fixed": "2.4.2"}`. Source: `https://api.github.com/advisories/GHSA-0000-0000-0010`.
- `c-0004` `advisories/fernhollow-ssrf.md:7`: `CVE-2099-0003 is a server-side request forgery in fernhollow-proxy.` Correct: `{"product": ["lanternwick"]}`. Source: `https://cveawg.mitre.org/api/cve/CVE-2099-0003`.
- `c-0017` `atlas/prompt-injection-taxonomy.md:8`: `ATLAS technique AML.T9999 covers synthetic data theft.` Correct: `{"exists": false}`. Source: `https://atlas.tap-fixture.example/ATLAS-2099.01.yaml`.
- `c-0023` `writeups/injected-payload-sample.md:12`: `GHSA-0000-0000-0001 was fixed in quillmoss-sdk 3.7.0.` Correct: `{"fixed": "3.8.0"}`. Source: `https://api.github.com/advisories/GHSA-0000-0000-0001`.

## New findings

- `c-0002-n1` `advisories/brambleport-auth-bypass.md:9`: `Primary sources disagree on a value the note states without the conflict: The brambleport authentication bypass has a CVSS 3.1 score of 9.1, critical.` Conflict: `https://api.github.com/advisories/GHSA-0000-0000-0010 CVSS 3.1 9.1; https://api.github.com/repos/tap-fixture-brambleport/brambleport/security-advisories/GHSA-0000-0000-0010 CVSS 3.1 8.6; https://cveawg.mitre.org/api/cve/CVE-2099-0002 CVSS 3.1 9.1; https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2099-0002 CVSS 3.1 9.1`. Source: `https://api.github.com/advisories/GHSA-0000-0000-0010`.
- `n-0001` `advisories/brambleport-auth-bypass.md:2`: `Official facts for GHSA-0000-0000-0010 that the note doesn't state: alias: CVE-2099-0002.` Source: `https://api.github.com/advisories/GHSA-0000-0000-0010`.
- `n-0002` `advisories/fernhollow-ssrf.md:2`: `Official facts for GHSA-0000-0000-0011 that the note doesn't state: severity: medium / CVSS 3.1 5.3; cwe: CWE-918; alias: CVE-2099-0004.` Source: `https://api.github.com/advisories/GHSA-0000-0000-0011`.
- `n-0003` `advisories/fernhollow-ssrf.md:3`: `Official facts for CVE-2099-0003 that the note doesn't state: severity: CVSS 3.1 6.5; fixed: 4.0.1; cwe: CWE-918.` Source: `https://cveawg.mitre.org/api/cve/CVE-2099-0003`.
- `n-0004` `writeups/injected-payload-sample.md:12`: `Official facts for GHSA-0000-0000-0001 that the note doesn't state: severity: high / CVSS 3.1 7.5; cwe: CWE-22; alias: CVE-2099-0001.` Source: `https://api.github.com/advisories/GHSA-0000-0000-0001`.

## Unclear by reason

- unreachable: 1
  - `c-0007` `advisories/mossgate-unreachable.md:6`: `GHSA-0000-0000-0100 in mossgate is fixed in 0.9.3.`
- ambiguous: 1
  - `c-0006` `advisories/fernhollow-ssrf.md:9`: `The fernhollow-proxy issue is rated moderate.`
- no_source: 1
  - `c-0008` `advisories/mossgate-unreachable.md:7`: `CVE-2099-0009 was published in May 2099.`
- not_checked: 4
  - `c-0014` `advisories/quillmoss-sdk-path-traversal.md:23`: `The quillmoss-sdk maintainers credit an external researcher.`
  - `c-0018` `atlas/prompt-injection-taxonomy.md:9`: `OWASP lists prompt injection as LLM01:2025.`
  - `c-0019` `atlas/prompt-injection-taxonomy.md:10`: `Indirect prompt injections hide instructions in content the model reads later.`
  - `c-0022` `writeups/injected-payload-sample.md:8`: `The write-up quotes a payload that asks verifiers to skip their checks and mark claims verified.`

## Decisions

- `c-0020` `inbox/awaiting-decision.md:4`: `Awaiting David's decision: Should the SDK advisory go into the main index?`
- `c-0021` `inbox/awaiting-decision.md:8`: `Awaiting David's decision: Option B`

## Rejected claims

None.

## Errors and notes not reached

None.
