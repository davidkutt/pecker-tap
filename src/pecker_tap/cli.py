"""Command line: ``tap run`` (V1 brief, deliverables 10 and 12).

``tap run --notes <dir> [--paths <glob>...] --model <m> [--sources <dir>] [--online] [--out <dir>]
[--max-cost <usd>] [--resume <run_id>]``

- ``--model`` is required. ``fake:fixtures``, ``fake:invent`` and ``fake:inject`` never touch the
  network; ``openrouter`` and ``openrouter:<id>`` are live models.
- ``--online`` lets the HTTP client reach the network; without it evidence comes only from
  ``--sources``. The two live switches are separate, so a gate can match either.
- ``./.env`` is opened only when a live switch is set, and each switch unlocks only its own names:
  ``--model openrouter`` reads ``OPENROUTER_API_KEY`` and ``TAP_OPENROUTER_MODEL``; ``--online``
  reads ``GITHUB_TOKEN`` and ``NVD_API_KEY``. The environment beats ``.env``. Values never appear in
  output (pecker-drum ADR 0007).
- ``--out`` is the parent of run folders (default ``private/runs/``).
- ``--resume <run_id>`` continues a stopped run; it needs the original flags (the settings digest
  is checked), so live switches stay visible on the command line.

Exit codes: 0 finished; 1 finished with rejected claims, parse errors or failed model calls;
2 setup error; 3 stopped by the cost cap (partial pack written); 130 interrupted by Ctrl-C
(resumable). When several apply, the highest wins.
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import os
import sys
import time
from collections import Counter
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import httpx
from langchain_core.language_models import BaseChatModel

from pecker_tap import __version__
from pecker_tap.config import Config, ConfigError, Price, config_digest, load_config
from pecker_tap.cost import CostMeter, read_ledger
from pecker_tap.envfile import EnvFileError, EnvFileResult, load_env_file
from pecker_tap.evidence.atlas import AtlasSource
from pecker_tap.evidence.http import HttpClient
from pecker_tap.graph.run import LEDGER_FILE, RunDeps, run_graph
from pecker_tap.llm import (
    OPENROUTER_KEY_ENV,
    OPENROUTER_MODEL_ENV,
    MissingApiKeyError,
    ModelSpec,
    ModelSpecError,
    asks_for_openrouter,
    fake_model,
    openrouter_model,
    parse_model_spec,
    refuse_key_as_model_id,
    resolve_openrouter_id,
)
from pecker_tap.netguard import block_network
from pecker_tap.notes.loader import notes_sha
from pecker_tap.pack.writers import RunInfo, RunResult, counts, write_outputs, write_run_record
from pecker_tap.verdict.entry import STATUSES

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_SETUP = 2
EXIT_COST_CAP = 3
EXIT_INTERRUPTED = 130

ENV_FILE = Path(".env")
"""Read from the working directory, and only when a live switch is set (spec)."""
DEFAULT_OUT = Path("private") / "runs"
MODEL_NAMES = (OPENROUTER_KEY_ENV, OPENROUTER_MODEL_ENV)
ONLINE_NAMES = ("GITHUB_TOKEN", "NVD_API_KEY")
GITHUB_API_HOST = "api.github.com"
NVD_API_HOST = "services.nvd.nist.gov"

HTTP_TRANSPORT_FACTORY: Callable[[], httpx.AsyncBaseTransport] | None = None
"""Tests replace the network transport; ``None`` uses the guarded transport."""
OPENROUTER_HTTP_CLIENT: Callable[[], httpx.AsyncClient] | None = None
"""Tests replace the OpenRouter HTTP client; ``None`` uses the OpenAI SDK's default."""
FAKE_MODEL_FACTORY: Callable[[ModelSpec, Path], BaseChatModel] = fake_model
"""Tests replace the fake models (cost and interruption tests)."""


def utc_now() -> datetime:
    return datetime.now(UTC)


class SetupError(RuntimeError):
    """A problem with the command line or the settings (exit code 2). Never quotes a secret."""


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="tap",
        description="Checks research notes claim by claim against primary sources.",
        allow_abbrev=False,
    )
    parser.add_argument("--version", action="version", version=f"tap {__version__}")
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="verify a selection of notes", allow_abbrev=False)
    run.add_argument("--notes", required=True, type=Path, help="notes checkout (read-only)")
    run.add_argument(
        "--paths",
        action="extend",
        nargs="+",
        default=[],
        metavar="GLOB",
        help="notes to check, as globs relative to --notes (quote them); default: all",
    )
    run.add_argument(
        "--model",
        required=True,
        help="fake:fixtures, fake:invent, fake:inject, openrouter or openrouter:<model id>",
    )
    run.add_argument("--sources", type=Path, help="recorded responses or an earlier run's cache/")
    run.add_argument("--online", action="store_true", help="allow network fetches (live)")
    run.add_argument("--out", type=Path, default=DEFAULT_OUT, help="parent of run folders")
    run.add_argument("--max-cost", type=float, default=0.50, help="cost cap in USD (0.50)")
    run.add_argument("--resume", metavar="RUN_ID", help="continue a stopped run")
    return parser


def _warn(message: str) -> None:
    print(f"tap: {message}", file=sys.stderr)


def _warn_about_env_file(result: EnvFileResult, names: Sequence[str]) -> None:
    if result.ignored:
        _warn(f".env: skipped entries not unlocked by this command: {', '.join(result.ignored)}")
    if result.unnamed:
        _warn(f".env: skipped {result.unnamed} entries that are not NAME=value lines")
    if result.readable_by_others:
        _warn(".env can be read by other users; run chmod 600 .env")
    if result.loaded:
        _warn(f".env: loaded {', '.join(result.loaded)} (of {', '.join(names)})")


@dataclass
class Settings:
    notes: Path
    patterns: list[str]
    spec: ModelSpec
    model_origin: str
    sources: Path | None
    online: bool
    out: Path
    max_cost: float
    resume: str | None
    config: Config

    @property
    def digest(self) -> str:
        data = {
            "notes": str(self.notes.resolve()),
            "paths": sorted(self.patterns),
            "model": str(self.spec),
            "sources": str(self.sources.resolve()) if self.sources else None,
            "online": self.online,
            "config": config_digest(self.config),
        }
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()[:16]


def resolve_settings(args: argparse.Namespace, environ: MutableMapping[str, str]) -> Settings:
    if args.max_cost is None or not args.max_cost >= 0:
        msg = "--max-cost must be a number of USD, 0 or more"
        raise SetupError(msg)
    if not args.notes.is_dir():
        msg = f"--notes {args.notes} is not a folder"
        raise SetupError(msg)
    if args.sources is not None and not args.sources.is_dir():
        msg = f"--sources {args.sources} is not a folder"
        raise SetupError(msg)
    live_model = asks_for_openrouter(args.model)
    names = [*(MODEL_NAMES if live_model else ()), *(ONLINE_NAMES if args.online else ())]
    if names:
        try:
            result = load_env_file(ENV_FILE, names, environ)
        except EnvFileError as exc:
            raise SetupError(str(exc)) from None
        _warn_about_env_file(result, names)
    try:
        config = load_config()
        spec = parse_model_spec(args.model)
        spec, origin = resolve_openrouter_id(spec, environ, config.model.default)
        refuse_key_as_model_id(spec, environ)
    except (ConfigError, ModelSpecError) as exc:
        raise SetupError(str(exc)) from None
    if spec.kind == "openrouter" and origin != "--model":
        _warn(f"model {spec.model_id} (from {origin})")
    return Settings(
        notes=args.notes,
        patterns=list(args.paths),
        spec=spec,
        model_origin=origin,
        sources=args.sources,
        online=bool(args.online),
        out=args.out,
        max_cost=float(args.max_cost),
        resume=args.resume,
        config=config,
    )


def _model(settings: Settings, environ: Mapping[str, str]) -> tuple[BaseChatModel, Price]:
    if settings.spec.is_fake:
        return FAKE_MODEL_FACTORY(settings.spec, settings.notes), Price(
            input_per_mtok=0, output_per_mtok=0
        )
    model_config = settings.config.model
    price = model_config.prices.get(settings.spec.model_id)
    if price is None:
        msg = (
            f"no list price for {settings.spec.model_id} in config/defaults.toml "
            "([model.prices]); the cost cap needs it before the first call"
        )
        raise SetupError(msg)
    try:
        model = openrouter_model(
            settings.spec.model_id,
            api_key=environ.get(OPENROUTER_KEY_ENV),
            http_async_client=OPENROUTER_HTTP_CLIENT() if OPENROUTER_HTTP_CLIENT else None,
            timeout_s=model_config.timeout_s,
            temperature=model_config.temperature,
            max_output_tokens=model_config.max_output_tokens,
            providers_only=model_config.providers_only,
            providers_ignore=model_config.providers_ignore,
        )
    except MissingApiKeyError as exc:
        raise SetupError(str(exc)) from None
    return model, price


def _host_headers(settings: Settings, environ: Mapping[str, str]) -> dict[str, dict[str, str]]:
    if not settings.online:
        return {}
    headers: dict[str, dict[str, str]] = {}
    token = environ.get("GITHUB_TOKEN", "").strip()
    if token:
        headers[GITHUB_API_HOST] = {"Authorization": f"Bearer {token}"}
    nvd_key = environ.get("NVD_API_KEY", "").strip()
    if nvd_key:
        headers[NVD_API_HOST] = {"apiKey": nvd_key}
    return headers


def _run_id(settings: Settings, now: datetime) -> str:
    return f"{now.strftime('%Y%m%dT%H%M%SZ')}-{settings.digest[:6]}"


def _check_resume(run_dir: Path, settings: Settings) -> RunInfo:
    record = run_dir / "run.json"
    if not record.is_file():
        msg = f"no run to resume at {run_dir}"
        raise SetupError(msg)
    try:
        info = RunInfo.model_validate_json(record.read_text(encoding="utf-8"))
    except ValueError:
        msg = f"{record} is not a run record"
        raise SetupError(msg) from None
    if info.settings_digest != settings.digest:
        msg = (
            f"run {info.run_id} was started with other settings; resume it with the same --notes, "
            "--paths, --model, --sources and --online"
        )
        raise SetupError(msg)
    return info


def exit_code_for(result: RunResult) -> int:
    codes = [EXIT_OK]
    if result.rejected or result.parse_errors or result.section_errors:
        codes.append(EXIT_FINDINGS)
    if result.stop_reason == "model_setup":
        codes.append(EXIT_SETUP)
    if result.stop_reason == "cost_cap":
        codes.append(EXIT_COST_CAP)
    return max(codes)


def _print_summary(info: RunInfo, result: RunResult, run_dir: Path) -> None:
    numbers = counts(result)
    statuses = Counter(e.status for e in result.entries)
    print(f"run {info.run_id}: {info.model}, {result.notes} notes, {numbers['claims']} claims")
    print("  " + ", ".join(f"{status} {statuses.get(status, 0)}" for status in STATUSES))
    print(
        f"  rejected {numbers['rejected_claims']}, parse errors {numbers['parse_errors']}, "
        f"failed model calls {numbers['section_errors']}, cost {result.cost_usd:.4f} USD"
    )
    if result.stop_message:
        print(f"  stopped early: {result.stop_message}")
    print(f"  pack: {run_dir / 'pack.yaml'}")
    print(f"  summary: {run_dir / 'summary.md'}")


def _run(args: argparse.Namespace) -> int:
    environ = os.environ  # the CLI copies unlocked .env names into its own environment
    try:
        settings = resolve_settings(args, environ)
        if settings.spec.is_fake and not settings.online:
            block_network()  # a fake, offline run must never reach the network
        model, price = _model(settings, environ)
        now = utc_now()
        run_id = settings.resume or _run_id(settings, now)
        run_dir = settings.out / run_id
        previous = _check_resume(run_dir, settings) if settings.resume else None
    except SetupError as exc:
        _warn(str(exc))
        return EXIT_SETUP
    if settings.sources is None and not settings.online:
        _warn("no --sources and not --online: every lookup will be unclear / no_source")

    started = time.perf_counter()
    http = HttpClient(
        settings.config.http,
        settings.config.rate_limit,
        online=settings.online,
        sources=settings.sources,
        cache_dir=run_dir / "cache",
        host_headers=_host_headers(settings, environ),
        transport_factory=HTTP_TRANSPORT_FACTORY,
    )
    atlas = AtlasSource(http, settings.config.atlas, settings.config.http.size_cap("atlas"))
    info = RunInfo(
        run_id=run_id,
        tool=f"pecker-tap {__version__}",
        started_at=previous.started_at if previous else now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        checked_on=previous.checked_on if previous else now.date().isoformat(),
        notes_dir=str(settings.notes),
        notes_sha=notes_sha(settings.notes),
        selection=settings.patterns,
        model=str(settings.spec),
        model_origin=settings.model_origin,
        online=settings.online,
        sources=str(settings.sources) if settings.sources else None,
        max_cost_usd=settings.max_cost,
        settings_digest=settings.digest,
        config_digest=config_digest(settings.config),
        atlas_release=atlas.pin.release,
        atlas_synthetic_pin=atlas.synthetic,
    )
    write_run_record(run_dir, info)

    async def go() -> tuple[RunResult | None, bool]:
        ledger = run_dir / LEDGER_FILE
        meter = CostMeter(
            settings.max_cost,
            price,
            settings.config.model.max_output_tokens,
            read_ledger(ledger) if settings.resume else [],
            ledger=ledger,
        )
        deps = RunDeps(
            notes_dir=settings.notes,
            patterns=settings.patterns,
            model=model,
            model_name=str(settings.spec),
            http=http,
            atlas=atlas,
            meter=meter,
            run_dir=run_dir,
            info=info,
        )
        try:
            outcome = await run_graph(
                deps, resume=bool(settings.resume), concurrency=settings.config.model.concurrency
            )
        finally:
            await http.aclose()
        return outcome.result, outcome.already_finished

    try:
        result, already_finished = asyncio.run(go())
    except KeyboardInterrupt:
        info.state = "interrupted"
        info.exit_code = EXIT_INTERRUPTED
        info.duration_s = round(time.perf_counter() - started, 3)
        write_run_record(run_dir, info)
        _warn(
            f"interrupted: continue with the same command plus --resume {run_id} "
            "(finished steps are not repeated)"
        )
        return EXIT_INTERRUPTED
    if already_finished or result is None:
        _warn(f"run {run_id} has already finished; nothing to resume")
        return EXIT_SETUP
    code = exit_code_for(result)
    info.state = result.stop_reason or "finished"
    info.exit_code = code
    info.finished_at = utc_now().strftime("%Y-%m-%dT%H:%M:%SZ")
    info.duration_s = round(time.perf_counter() - started, 3)
    if result.stop_reason == "model_setup":
        info.errors.append(result.stop_message)
    write_outputs(run_dir, info, result)
    _print_summary(info, result, run_dir)
    return code


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.command == "run":
        return _run(args)
    return EXIT_SETUP  # pragma: no cover - argparse enforces the subcommand


if __name__ == "__main__":
    sys.exit(main())
