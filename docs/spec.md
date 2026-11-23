# pecker-tap spec

Status: draft, 23 November 2026. Written in the planning chat before V1; no ADRs yet except 0001.

## Purpose

Check research notes claim by claim against primary sources, the way a careful reviewer would, and
say for each claim what holds, what a primary source contradicts, which official facts are missing,
and what can't be settled without guessing. The output is a verification pack that David reviews;
the verifier never edits notes.

The notes are David's private Markdown knowledge base on AI security and bug bounty work. A research
bot (Magpie) writes new notes into an inbox; a verification bot (Wren, Grok-based) checks them claim by
claim; David decides and promotes. pecker-tap is a second, independent verifier:

- **Different model family** than the research bot, so its mistakes don't line up with the bot's.
- **Code where code can decide.** Advisory IDs, scores, CWEs, versions and dates come from official
  APIs and are compared by code. An LLM judges only wording.
- **Measured.** Every claim of past runs has a human verdict, so the verifier gets numbers: how many
  real contradictions it catches, how often it cries wolf, how often it says "unclear", what it costs.

A woodpecker taps bark to find hollow wood. Same job.

## Inputs and outputs

**Input:** a local checkout of the notes repository (read-only), a selection of notes (paths, or the
notes changed in a git range such as a research PR), and a model. The run records the checkout's
commit SHA. The verifier never writes to that checkout and never talks to GitHub with write access.

**Output** (one folder per run, default `private/runs/<run_id>/`):

| File | Content |
| --- | --- |
| `pack.yaml` | One entry per claim (schema below). Compatible with Wren's per-claim YAML, plus extra fields. |
| `summary.md` | Counts per status, contradictions, new findings, unclear claims with reasons. German from V3. |
| `report.json` | Everything in machine-readable form, including per-call model usage and cost. |
| `run.json` | Run record: notes SHA, selection, model, settings digest, timings, errors. |
| `delta.md` (V3) | Corrections David approved, as a request to the research bot. |

Run folders hold full note text and source excerpts, so they live under `private/` by default.

## Claims

A claim is one atomic, checkable statement taken from a note.

```yaml
- claim_id: c-0007                     # stable within a run: note order, then position
  note_path: notes/advisories/example.md
  lines: [41, 41]
  quote: "fixed in 3.7.0"              # exact substring of the note; checked by code
  text: "Package example-sdk is fixed in version 3.7.0 (GHSA-xxxx-xxxx-xxxx)."
  type: version                         # see the type table
  entities: {ghsa: [GHSA-xxxx-xxxx-xxxx], cve: [], atlas: [], owasp: [], urls: []}
  cited_urls: ["https://github.com/example/sdk/security/advisories/GHSA-xxxx-xxxx-xxxx"]
  value: {fixed: "3.7.0"}               # normalised value for structured types; null for prose
```

| Type | Examples | Checked by |
| --- | --- | --- |
| `identifier` | a CVE or GHSA exists, belongs to this product, aliases match | code (advisory APIs) |
| `severity` | label, CVSS version, base score, vector | code |
| `weakness` | CWE IDs | code |
| `version` | affected range, fixed version, "no fix yet" | code |
| `date` | published, fixed, disclosed, reported | code, else judge |
| `product` | the affected product or package, the vendor | code where an API names it, else judge |
| `taxonomy` | ATLAS IDs and names (version pinned), OWASP IDs with year | code (ATLAS YAML, OWASP tables) |
| `scope_payout` | bounty scope, payout figures, program rules | judge, official program page only |
| `prose` | what a write-up or spec says | judge |
| `decision` | items the note marks as David's decision | never checked; listed as decisions |

**Extraction** is an LLM step with structured output, one call per note section. Code rejects any
claim whose `quote` is not an exact substring of the note at the given lines, so the extractor can't
invent claims. Notes marked `decision: awaiting-david` yield only `decision` entries.

## Statuses

The four statuses of Wren's packs, with the same meaning, plus reasons and conflicts:

| Status | Meaning |
| --- | --- |
| `verified` | A primary source supports the claim as worded. |
| `contradicted` | A clear primary source disagrees. The entry gives the correct value and its source. |
| `new_finding` | An official fact the note lacks: a missing score, a second conflict, a later fix. |
| `unclear` | Can't be settled without guessing. `reason` is one of `unreachable` (403, 429, login, bot wall, empty page), `secondary_only`, `ambiguous`, `no_source`, `not_checked`. |

Rules that decide between them:

1. **No evidence, no verdict.** Missing or unreadable evidence gives `unclear`, never a guess.
2. **Primary before secondary.** Press, aggregators and summaries are hints. A claim that only a
   secondary source supports is `unclear` with reason `secondary_only`. Which domains count as
   secondary is configured (`config/sources.toml`), not decided by the model.
3. **Primaries that disagree** (repository advisory vs global database, NVD vs CNA, badge vs body):
   every value is recorded with its source in `conflict`. If the note states one of the values and
   records the conflict, the claim is `verified`. If it states one of them without the conflict, the
   claim is `verified` and a separate `new_finding` records the conflict. If it states none of them,
   it is `contradicted`. The verifier never picks a winner.
4. **Archived copies** (Wayback) count as the source they copy, flagged `archived: true`.
5. **Never fix silently.** Typos and wording issues are entries, not edits.

### Pack entry

```yaml
- claim_id: c-0007
  status: contradicted                  # verified | contradicted | new_finding | unclear
  reason: null                          # set for unclear
  note_path: notes/advisories/example.md
  lines: [41, 41]
  claim: "Package example-sdk is fixed in version 3.7.0."
  source_url: "https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx"
  evidence: "first_patched_version: 3.8.0"   # at most 300 characters, escaped
  note: "Global advisory and repository advisory both list 3.8.0 as the first patched version."
  correct_value: {fixed: "3.8.0"}       # for contradicted
  conflict: null                        # or a list of {source_url, value}
  decided_by: code                      # code | judge
  archived: false
  checked_on: 2026-11-23
```

Field names that also exist in Wren's packs (`claim_id`, `status`, `note_path`, `source_url`, and
`note` for free text) keep Wren's names and meaning, so packs can be compared field by field.

## Evidence

Evidence is gathered in this order and stops at the first source that settles the claim:

1. **Structured APIs** (no LLM): GitHub global advisory API (`/advisories/{ghsa}`) and repository
   advisory API (`/repos/{owner}/{repo}/security-advisories/{ghsa}`), CVE.org (CVE Services
   `cveawg.mitre.org/api/cve/{id}`), NVD API 2.0, the ATLAS YAML of a pinned release, OWASP tables
   kept in `data/owasp/` with their year, HackerOne public report JSON.
2. **Cited URLs** from the claim or the note's `sources`, fetched as plain HTTP (no JavaScript, no
   cookies, no login), HTML converted to text, size-capped. Long pages are split and indexed with
   LlamaIndex; the judge sees the top passages for the claim, with their offsets.
3. **Wayback** copy of a cited URL when the live page is gone, flagged as archived.

The verifier never searches the web for new sources: it checks what the note cites plus the
structured APIs. A claim with nothing to check is `unclear` with reason `no_source`.

**No network by default.** Without `--online`, evidence comes only from `--sources <dir>`: recorded
fixtures, the cache of an earlier run, or a source snapshot with a manifest (`manifest.csv`: path,
original_url, fetched_at, http_status, method, sha256, claim_ids). The manifest is the format of
Wren's raw-copy export, so an evaluation can use exactly the pages Wren saw. A source that isn't there
gives `unclear` with reason `no_source`. `--online` lets the HTTP client reach the network; every
response is cached in the run folder and can be replayed as `--sources` later. A live model and live
fetching are separate switches (`--model openrouter`, `--online`), so a gate can match either.

## Graph (LangGraph)

```
load_notes ──> extract (per note) ──> fan out per claim (Send)
                                         │
                       ┌─────────────────┴─────────────────┐
                 structured type                      prose or no API answer
                 api_lookup ──> compare (code)        fetch ──> passages (LlamaIndex) ──> judge (LLM)
                       └─────────────────┬─────────────────┘
                                      collect ──> write_pack ──> [V3] review (interrupt) ──> write_delta
```

- A SQLite checkpointer saves every step: a stopped run resumes, and from V3 the review step waits
  for David's answers for as long as it takes.
- Concurrency is limited per host (API rate limits) and per model.

## Untrusted input

Notes quote prompt injections on purpose (attack taxonomies, payload examples), and fetched pages are
written by strangers. Both are data.

- Prompts wrap notes and evidence in delimiters and say they are data. Code strips or escapes any
  occurrence of the closing delimiter and of the verifier's own tag names inside the data first.
- The model has **no tools with side effects**. Extraction and judging are structured-output calls;
  every fetch is done by code, from the claim's cited URLs and the fixed API hosts only.
- Fetch limits: `https` only, at most 5 redirects (each recorded), response size and time caps, no
  private or loopback addresses, a user agent that names the tool.
- A quote the judge returns must be an exact substring of the evidence it was given; otherwise the
  verdict is discarded and the claim becomes `unclear` (`ambiguous`).
- Excerpts in reports are escaped (invisible and control characters as `\u…`) and capped.

## Model and settings

- Model access through OpenRouter with zero data retention enforced (`provider.zdr`), like
  pecker-drum. Default model: `deepseek/deepseek-v4.1-flash`. Providers can be pinned or excluded in
  the config. If no endpoint satisfies the settings, the run stops with a clear error.
- `--model` is required: `fake:<script>` for tests and self-tests, `openrouter` or
  `openrouter:<id>` for live runs. Only a live `--model` opens `./.env`, and only these names are read
  from it: `OPENROUTER_API_KEY`, `TAP_OPENROUTER_MODEL`, `GITHUB_TOKEN` (optional, public data only,
  raises the advisory API rate limit), `NVD_API_KEY` (optional). Environment beats `.env`. Values
  never appear in output (same rules as pecker-drum's ADR 0007).
- **Cost cap** per run, default 0.50 USD (`--max-cost`). The cost of each call comes from OpenRouter's
  reported usage; the run stops before a call that could cross the cap and says how far it got.

Planning estimate for DeepSeek V4.1 Flash (23 November 2026, list prices): about 0.10 to 0.30 USD per
100 claims, depending on provider and time of day. The first live run replaces this with real numbers.

## Evaluation

The point of the project is that its quality is measured, not asserted. ADR 0001 records why the
labels are David's verdicts and not Wren's.

**Data** (private, frozen per version, under `private/gold/`):

| Set | Content | Use |
| --- | --- | --- |
| `dev_w47` | The 2026-W47 notes as they stood when Wren checked them; Wren's per-claim statuses with David's decisions applied (about 200 labelled claims, about 10 contradictions) | Building and tuning |
| `holdout_w48` | The 2026-W48 notes at the research PR's merge commit; labels once Wren's pack and David's decisions exist | Final numbers only, once per version; never used to tune prompts |
| `planted_*` | Copies of verified notes with one fact changed each (below) | Recall on contradictions |

**Label import:** `tap gold import` reads Wren's pack YAML (both shapes in use) and an overlay file
with David's decisions (accepted, or overridden with the correct status and value) and writes the
gold set. Public code, tested with synthetic packs; David runs it on the private packs.

**Two modes:**

- **Given claims:** the gold set's claim list goes straight to evidence and judging. This measures
  the checking itself, claim for claim, with nothing lost to extraction.
- **End to end:** the verifier extracts its own claims; code aligns them to gold claims by note,
  line overlap and entities; the report lists unmatched claims both ways. This measures the whole
  tool, including what extraction misses.

**Planted errors** (`tap plant`): about 10 real contradictions are too few to measure how many get
caught; one miss moves the rate by ten points. So copies of verified notes get exactly one fact
changed each, of the kinds that slip through in practice: a fixed version, a date, a score, a CWE,
the product (taken from a title instead of the affected-products list), an identifier that belongs to
another product, a primary source replaced by a secondary one. Each copy records the change; the
expected status of the changed claim is `contradicted`. Unchanged copies run alongside as controls.
Fixed seed, private, never in this repo.

**Metrics,** each with a 95 % interval (method in an ADR in V2; see pecker-drum's ADR 0006 for the
approach):

- Recall on contradictions (real and planted), the main number: missed contradictions cost most.
- Precision of `contradicted` and false-contradiction rate on gold-`verified` claims.
- Confusion matrix over the four statuses; `unclear` rate with reasons.
- Agreement with Wren on the same claims; every disagreement goes to blind adjudication (V3).
- End-to-end only: share of gold claims the extractor found.
- Cost and time per claim. Stability over 3 repeats per run (claims whose status changes).

## Public and private

| Public (this repo) | Private (`private/`, git-ignored, never read by coding agents) |
| --- | --- |
| Code, tests, docs | Real notes, packs, run folders |
| Synthetic notes and recorded API responses in `fixtures/` (placeholder IDs that can't match real advisories, reserved domains `*.example` and `*.invalid`; see AGENTS.md) | Wren's packs and raw-copy export, gold sets, overlays, planted copies |
| Report formats and example reports from synthetic runs | Reports of real runs; David shares numbers by choice |

Never in tracked files: real note content, anything from Wren's packs, names of bug bounty programs'
customers, David's employer.

## Milestones

| Milestone | Content |
| --- | --- |
| V1 | Skeleton, CI, notes loader, claim extraction, advisory and ATLAS lookups, code comparison, pack writer, cost cap, first live run on a few real notes |
| V2 | Cited-URL evidence, LlamaIndex passages, LLM judge, offline mode, gold import, planted errors, `tap eval`; first evaluation on `dev_w47` |
| V3 | Review step with LangGraph interrupt, delta request, German summary, research-PR runs, blind adjudication, holdout numbers on `holdout_w48` |
| Later | pecker-drum attacks the verifier (success: a false claim comes out `verified`); cross-note conflicts through Grove's MCP search |
