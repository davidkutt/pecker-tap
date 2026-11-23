# pecker-tap

A woodpecker taps bark to find hollow wood. pecker-tap taps research notes: it breaks each note into
atomic claims, checks every claim against primary sources, and writes a verification pack that says
what holds, what a primary source contradicts, which official facts are missing, and what can't be
settled without guessing.

**Status:** planning done; V1 is next ([brief](docs/milestones/V1.md)).

## Why

Research agents write fast and are often wrong in small, costly ways: a fix date taken from a news
article instead of the vendor's timeline, a product guessed from an advisory's title, a CVE that
belongs to a different product. A second LLM agent checking the first catches some of it, but when
both run on the same model family their mistakes line up.

pecker-tap is built to be the other kind of second opinion:

- **Code decides where code can.** Advisory IDs, CVSS scores, CWEs, affected versions, fixed versions
  and dates come from official APIs (GitHub advisories, CVE.org, NVD, MITRE ATLAS) and are compared by
  code. An LLM judges only wording, and its quotes must appear verbatim in the evidence.
- **No evidence, no verdict.** Unreachable pages, secondary-only sources and ambiguous text give
  `unclear` with a reason, never a guess. Conflicting primary sources are recorded side by side.
- **Measured, not asserted.** The verifier is evaluated against human-adjudicated verdicts on real
  notes, plus planted errors, with intervals on every rate. See the
  [spec](docs/spec.md#evaluation) and [ADR 0001](docs/adr/0001-labels-are-davids-verdicts.md).
- **Built for hostile input.** The notes quote prompt injections on purpose and the sources are
  written by strangers; the model has no tools, code does every fetch, and a planted injection is
  part of the test fixtures.

## How it works

LangGraph runs the pipeline: load notes, extract claims (LangChain, structured output), fan out per
claim, look up official APIs or fetch the cited pages, find the relevant passages (LlamaIndex),
decide by code or by a judge, and write the pack. A review step pauses for a human decision on every
proposed correction before anything is handed back to the research loop.

Details: [docs/spec.md](docs/spec.md). Milestones: [V1](docs/milestones/V1.md),
[V2](docs/milestones/V2.md), [V3](docs/milestones/V3.md).

## Data

The notes and every evaluation set are private. This repository holds code, docs and synthetic
fixtures only; reports of real runs stay private, and their numbers are shared by choice.

## Licence

MIT
