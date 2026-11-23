# ADR 0002: An offline `--sources` folder may pin its own ATLAS release

Status: proposed (V1 coding session, 23 November 2026; for David to accept or change)

## Context

The V1 brief pins the ATLAS YAML in config (release `v2026.10`, URL, sha256 and collection version)
and requires the loader to check both. It also requires a synthetic ATLAS file in the tests and an
offline self-test, `tap run --notes fixtures/notes --model fake:fixtures --sources fixtures/http`,
whose fixtures include an ATLAS ID that doesn't exist in the pinned release.

The three don't fit together as written: the self-test command has no switch for another pin, the
real release can't be in the fixtures (agents don't fetch it, and it isn't synthetic), and a
synthetic file can never match the real sha256.

## Decision

1. A `--sources` folder may hold `pins.toml` with an `[atlas]` table: `release`, `url`, `sha256` and
   `collection_version`, the same fields as the pin in `config/defaults.toml`.
2. **Offline runs only.** Without `--online`, a run from that folder uses its pin instead of the
   configured one, and still checks the file's sha256 and collection version against it. With
   `--online` the file is ignored and the configured pin applies.
3. **Always visible.** `run.json`, `report.json` and `summary.md` name the release used and flag a
   pin that came from `--sources` (`atlas_synthetic_pin: true`, "synthetic pin from --sources").
4. The fixtures use it: `fixtures/http/pins.toml` pins a synthetic release served from
   `https://atlas.tap-fixture.example/ATLAS-2099.01.yaml`, so synthetic content is never filed under
   the real release's URL.

## Consequences

- The self-test runs the real loader, including both checks, on a synthetic release.
- No new trust is granted: offline, the `--sources` folder is already the whole evidence base. It
  could hold any advisory response, so letting it name its ATLAS file changes nothing an attacker
  with write access to it couldn't do anyway. Online, the configured pin is the only one.
- An earlier run's `cache/` replayed as `--sources` has no `pins.toml` and uses the configured pin,
  which matches the real file it cached.

## Alternatives considered

- **A `--config` or `--atlas-pin` switch:** more command-line surface for one test need, and a way to
  weaken the pin in live runs too.
- **Skipping the hash check offline:** a replayed cache would then accept a changed file.
- **No ATLAS in the self-test:** leaves the "ATLAS ID not in the pinned release" case of the brief
  untested end to end.
