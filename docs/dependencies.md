# Dependencies

Runtime dependencies (pinned to a minor version in `pyproject.toml`). All direct dependencies use
permissive licences (MIT, Apache-2.0, BSD, ISC). Unmodified transitive dependencies under MPL-2.0
are allowed, as in pecker-drum (its ADR 0005).

| Package | Licence | Why |
| --- | --- | --- |
| `pydantic` | MIT | Claim, record and pack schemas with strict validation (unknown fields rejected) |
| `langchain-core` | MIT | Chat-model base class and structured output (extraction; scripted fake models) |
| `langchain-openai` | MIT | OpenAI-compatible client for OpenRouter (live runs, `provider.zdr`) |
| `langgraph` | MIT | Run graph (fan-out with `Send`, concurrency limit) |
| `langgraph-checkpoint-sqlite` | MIT | SQLite checkpointer in the run folder, so `--resume` continues a stopped run |
| `httpx` | BSD-3-Clause | The single HTTP client (`evidence/http.py`) with an injectable transport |
| `httpcore` | BSD-3-Clause | Network backend under httpx; the guarded backend checks every resolved address before it connects |
| `pyyaml` | MIT | Note frontmatter, the ATLAS YAML and `pack.yaml` (`safe_load` / `safe_dump` only) |
| `packaging` | Apache-2.0 OR BSD-2-Clause | PEP 440 versions and ranges for pip advisories |
| `semver` | BSD-3-Clause | Semantic versions for npm, crates.io and Go advisories |
| `python-dotenv` | BSD-3-Clause | Parses `.env` for live runs (spec, Model and settings); no dependencies of its own |

Development dependencies:

| Package | Licence | Why |
| --- | --- | --- |
| `ruff` | MIT | Lint and format |
| `pyright` | MIT | Type checks (strict on `src/` and `tools/`) |
| `pytest` | MIT | Tests |
| `pytest-asyncio` | Apache-2.0 | Async tests |
| `types-pyyaml` | Apache-2.0 | Type stubs for PyYAML |

`[tool.uv] exclude-newer-package` holds `types-pyyaml` back to a release older than Dependabot's
seven-day cooldown; the next Dependabot update can lift it.

## Transitive MPL-2.0 dependencies (allowed)

| Package | Licence | Pulled in by |
| --- | --- | --- |
| `certifi` | MPL-2.0 | `httpx` (also the OpenAI client) |
| `orjson` | MPL-2.0 AND (Apache-2.0 OR MIT) | `langgraph-sdk` (via `langgraph`) |

Two other transitive licences are permissive but not in the list above: `typing-extensions`
(PSF-2.0) and `regex` (Apache-2.0 AND CNRI-Python, via `tiktoken`).

## CI tools (not dependencies)

CI runs two tools through `uvx`, each in a throwaway environment. They are not project
dependencies: they are not in `pyproject.toml` or `uv.lock`, and they never ship with pecker-tap.

| Tool | Version | Licence | Why |
| --- | --- | --- | --- |
| `pip-audit` | 2.10.1 | Apache-2.0 | Known vulnerabilities in the locked dependencies (job `audit`) |
| `zizmor` | 1.32.0 | MIT | Lint for the workflows and the Dependabot configuration (job `zizmor`) |

Both versions are pinned in the `run:` lines of `.github/workflows/ci.yml` and are **updated by
hand**: Dependabot updates the pinned actions and `uv.lock`, but not versions inside `run:` lines.
To bump one, read its release notes, run it locally with the new version (`uvx pip-audit@<version>`,
`uvx zizmor@<version>`), fix what it reports and change the version in the workflow and in this
table in the same pull request.
