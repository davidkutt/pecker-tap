# ADR 0001: Labels are David's verdicts, not Wren's

Status: accepted (David, 23 November 2026, planning chat)

## Context

pecker-tap is evaluated on notes that Wren, an existing verification bot, has already checked claim
by claim. The obvious label for a claim is Wren's status. But Wren is not ground truth:

- Wren and the research bot share a model family, so some of their mistakes line up.
- The record already shows a case where Wren was wrong: a correction Wren proposed did not hold up
  when David's delta PR re-fetched the primary source, and only the part the source supported was
  applied.
- Scoring against Wren rewards copying Wren. A verifier that is right where Wren is wrong would be
  marked down for it.

What David decided is on record: delta PRs apply the corrections he approved and list the ones not
applied, with reasons.

## Decision

1. **A gold label is David's verdict.** Where David accepted Wren's status, it becomes the label.
   Where he did not (a correction not applied, a status overridden), his decision is the label. An
   overlay file next to each imported pack records these decisions, one line per affected claim.
2. **Agreement with Wren is reported, never optimised.** It is one metric among several, next to the
   metrics against the gold labels.
3. **Disagreements get blind adjudication** (V3). For every claim where pecker-tap and Wren disagree,
   David sees the claim and both verdicts with their evidence, in random order and without saying
   which tool gave which, and picks one or neither. His pick updates the gold label for the next
   evaluation version; the current version stays frozen.
4. **Claims without a decision** (a pack David has not ruled on yet) carry Wren's status marked
   `provisional` and are reported separately until David decides.
5. **The holdout set is never tuned on.** Prompts and thresholds are tuned on `dev_w47` and planted
   errors only. `holdout_w48` gives numbers once per version.

## Consequences

- Labelling costs David time, so it is spent where it matters: overlays only for claims he did not
  accept as Wren put them, adjudication only for disagreements.
- The gold set improves with every adjudication round; reports name the gold version they used.
- A planted error's label comes from the planting script, not from either tool or from David.
