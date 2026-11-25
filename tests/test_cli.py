"""End-to-end runs of ``tap run`` on the synthetic fixtures (V1 brief, acceptance checks)."""

from __future__ import annotations

import json
import os
import re
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import httpx
import pytest
import yaml
from golden import DEFAULT_EXPECTED, compare, find_run
from langchain_core.messages import BaseMessage

from pecker_tap import cli
from pecker_tap.claims.prompt import unescape_attr
from pecker_tap.config import Price
from pecker_tap.evidence.http import GuardedTransport, ResponseStore
from pecker_tap.llm import FixtureChatModel, ModelSpec
from pecker_tap.pack.writers import RunInfo, RunResult

ROOT = Path(__file__).resolve().parents[1]
NOTES = ROOT / "fixtures" / "notes"
SOURCES = ROOT / "fixtures" / "http"
OPENROUTER_KEY = "sk-or-v1-LEAKTEST-0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b"
GITHUB_TOKEN = "github_pat_LEAKTEST_9z8y7x6w5v4u3t2s1r0q9p8o7n6m5l4k3j2i1h"


@pytest.fixture(autouse=True)
def _repo_root(monkeypatch: pytest.MonkeyPatch) -> None:
    """Golden files record relative paths, as CI passes them."""
    monkeypatch.chdir(ROOT)


def run(out: Path, *extra: str, model: str = "fake:fixtures", sources: bool = True) -> int:
    args = ["run", "--notes", "fixtures/notes", "--model", model, "--out", str(out), *extra]
    if sources:
        args += ["--sources", "fixtures/http"]
    return cli.main(args)


def pack(run_dir: Path) -> list[dict[str, Any]]:
    return yaml.safe_load((run_dir / "pack.yaml").read_text(encoding="utf-8"))


def report(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "report.json").read_text(encoding="utf-8"))


def by_claim(entries: list[dict[str, Any]]) -> dict[tuple[str, int, str], str]:
    """Status per claim, keyed by what survives renumbering: note, first line, claim text."""
    return {
        (e["note_path"], e["lines"][0], e["claim"]): e["status"]
        for e in entries
        if e["claim_id"].startswith("c-") and "-n" not in e["claim_id"]
    }


# --- the self-test -----------------------------------------------------------------------------


def test_self_test_reproduces_the_golden_files(tmp_path: Path) -> None:
    assert run(tmp_path) == cli.EXIT_OK
    assert compare(find_run(tmp_path), DEFAULT_EXPECTED) == []


def test_the_network_transport_is_never_reached(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def refuse(*args: object, **kwargs: object) -> None:
        raise AssertionError("the network transport must not be built or used in a self-test")

    monkeypatch.setattr(GuardedTransport, "__init__", refuse)
    monkeypatch.setattr(GuardedTransport, "handle_async_request", refuse)
    assert run(tmp_path) == cli.EXIT_OK


def test_every_fixture_record_matches_its_body() -> None:
    store = ResponseStore(SOURCES)
    urls = [json.loads(p.read_text())["url"] for p in SOURCES.glob("*.json")]
    assert len(urls) >= 14
    for url in urls:
        result = store.get(url, "sources")
        assert result is not None
        assert getattr(result, "kind", None) != "bad_record", f"{url}: sha256 does not match"


# --- hostile and inventing extractors ----------------------------------------------------------


def test_planted_injection_changes_nothing(tmp_path: Path) -> None:
    assert run(tmp_path / "fixtures") == cli.EXIT_OK
    assert run(tmp_path / "inject", model="fake:inject") == cli.EXIT_FINDINGS  # rejected claims
    expected = by_claim(pack(find_run(tmp_path / "fixtures")))
    injected_run = find_run(tmp_path / "inject")
    got = by_claim(pack(injected_run))
    # Every claim of the clean run keeps its status.
    assert {key: got[key] for key in expected} == expected
    # The claims the payload asked for: rejected, or kept with the status code gives them.
    extra = {key: status for key, status in got.items() if key not in expected}
    assert extra, "fake:inject adds claims"
    assert "verified" not in extra.values()
    assert sorted(extra.values()) == ["contradicted", "unclear"]
    reasons = sorted(r["reason"] for r in report(injected_run)["rejected"])
    assert reasons == ["quote_not_found", "schema"]
    # The marker phrase never becomes a status or a verdict.
    marked = [e for e in pack(injected_run) if "TAP-MARKER-7" in e["claim"]]
    assert [(e["status"], e["reason"]) for e in marked] == [("unclear", "not_checked")]


def test_invented_claims_are_all_rejected_and_listed(tmp_path: Path) -> None:
    assert run(tmp_path, model="fake:invent") == cli.EXIT_FINDINGS
    run_dir = find_run(tmp_path)
    data = report(run_dir)
    fixture_claims = sum(
        len(yaml.safe_load(p.read_text(encoding="utf-8"))) for p in NOTES.rglob("*.claims.yaml")
    )
    assert len(data["rejected"]) == fixture_claims
    assert {r["reason"] for r in data["rejected"]} == {"quote_not_found"}
    kept = [e for e in data["entries"] if e["claim_id"].startswith("c-")]
    assert {e["type"] for e in kept} == {"decision"}  # only the note that needs no model call
    summary = (run_dir / "summary.md").read_text(encoding="utf-8")
    assert summary.count("quote_not_found") == fixture_claims


# --- cost cap and resume -----------------------------------------------------------------------


def test_cost_cap_stops_cleanly_and_writes_what_it_has(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def costly(spec: ModelSpec, notes: Path) -> FixtureChatModel:
        return FixtureChatModel(notes_root=str(notes), mode=spec.fake_mode, cost_per_call=0.2)

    original = cli._model  # pyright: ignore[reportPrivateUsage]

    def priced(settings: Any, environ: Any) -> tuple[Any, Price]:
        # A list price that makes the first-call estimate (4096 output tokens) about 0.2 USD,
        # so the calls that start together before any cost is known are capped too.
        model, _ = original(settings, environ)
        return model, Price(input_per_mtok=1.0, output_per_mtok=50.0)

    monkeypatch.setattr(cli, "FAKE_MODEL_FACTORY", costly)
    monkeypatch.setattr(cli, "_model", priced)
    assert run(tmp_path, "--max-cost", "0.5") == cli.EXIT_COST_CAP
    run_dir = find_run(tmp_path)
    data = report(run_dir)
    assert data["counts"]["model_calls"] == 2  # 0.2 + 0.2; a third could reach 0.6
    assert data["counts"]["cost_usd"] == pytest.approx(0.4)
    assert data["stop_reason"] == "cost_cap"
    assert data["not_reached"]
    assert data["run"]["state"] == "cost_cap"
    assert data["run"]["exit_code"] == cli.EXIT_COST_CAP
    assert "Stopped early" in (run_dir / "summary.md").read_text(encoding="utf-8")
    assert "stopped early" in capsys.readouterr().out
    # Claims from the notes it reached are still checked by code.
    assert data["entries"]


class _Interrupting(FixtureChatModel):
    interrupt_on: int = 0
    calls: Any = None
    """A list shared with the test (typed Any so Pydantic doesn't copy it)."""

    async def _agenerate(self, messages: list[BaseMessage], *args: Any, **kwargs: Any) -> Any:
        self.calls.append(1)
        if self.interrupt_on and len(self.calls) == self.interrupt_on:
            raise KeyboardInterrupt
        return self._generate(messages, *args, **kwargs)


def test_resume_after_ctrl_c_does_not_repeat_finished_notes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[int] = []

    def interrupting(spec: ModelSpec, notes: Path) -> FixtureChatModel:
        return _Interrupting(notes_root=str(notes), interrupt_on=6, calls=calls)

    monkeypatch.setattr(cli, "FAKE_MODEL_FACTORY", interrupting)
    assert run(tmp_path) == cli.EXIT_INTERRUPTED
    run_dir = find_run(tmp_path)
    info = RunInfo.model_validate_json((run_dir / "run.json").read_text(encoding="utf-8"))
    assert (info.state, info.exit_code) == ("interrupted", cli.EXIT_INTERRUPTED)
    assert (run_dir / "checkpoint.sqlite").is_file()
    assert f"--resume {info.run_id}" in capsys.readouterr().err

    resumed_calls: list[int] = []

    def counting(spec: ModelSpec, notes: Path) -> FixtureChatModel:
        return _Interrupting(notes_root=str(notes), calls=resumed_calls)

    monkeypatch.setattr(cli, "FAKE_MODEL_FACTORY", counting)
    assert run(tmp_path, "--resume", info.run_id) == cli.EXIT_OK
    assert 0 < len(resumed_calls) < 9  # a full run makes 9 calls; finished notes are kept
    assert compare(run_dir, DEFAULT_EXPECTED, ["pack.yaml"]) == []
    # The report counts the calls recorded as paid, a call repeated after Ctrl-C included. A call
    # cancelled by Ctrl-C before its answer was recorded can't be counted.
    paid = report(run_dir)["counts"]["model_calls"]
    assert 9 <= paid <= len(calls) - 1 + len(resumed_calls)
    # A finished run has nothing left to resume.
    assert run(tmp_path, "--resume", info.run_id) == cli.EXIT_SETUP


def test_resume_refuses_other_settings(tmp_path: Path) -> None:
    assert run(tmp_path) == cli.EXIT_OK
    run_id = find_run(tmp_path).name
    assert run(tmp_path, "--resume", run_id, model="fake:invent") == cli.EXIT_SETUP
    assert run(tmp_path, "--resume", "20990101T000000Z-000000") == cli.EXIT_SETUP


def test_a_run_without_out_writes_under_private_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    code = cli.main(
        ["run", "--notes", str(NOTES), "--sources", str(SOURCES), "--model", "fake:fixtures"]
    )
    assert code == cli.EXIT_OK
    [run_dir] = list((tmp_path / "private" / "runs").iterdir())
    assert {"pack.yaml", "summary.md", "report.json", "run.json", "checkpoint.sqlite"} <= {
        p.name for p in run_dir.iterdir()
    }


# --- exit codes and setup errors ---------------------------------------------------------------


def test_highest_exit_code_wins() -> None:
    from pecker_tap.claims.extract import SectionError
    from pecker_tap.claims.schema import RejectedClaim

    rejected = RejectedClaim(note_path="a.md", reason="schema")
    failed = SectionError(note_path="a.md", section=0, message="x")
    assert cli.exit_code_for(RunResult()) == 0
    assert cli.exit_code_for(RunResult(rejected=[rejected])) == 1
    assert cli.exit_code_for(RunResult(section_errors=[failed])) == 1
    assert cli.exit_code_for(RunResult(rejected=[rejected], stop_reason="model_setup")) == 2
    assert cli.exit_code_for(RunResult(rejected=[rejected], stop_reason="cost_cap")) == 3


@pytest.mark.parametrize(
    "args",
    [
        ["run", "--notes", "no-such-folder", "--model", "fake:fixtures"],
        ["run", "--notes", "fixtures/notes", "--model", "fake:obedient"],
        ["run", "--notes", "fixtures/notes", "--model", "fake:fixtures", "--max-cost", "-1"],
        ["run", "--notes", "fixtures/notes", "--model", "fake:fixtures", "--sources", "nope"],
        ["run", "--notes", "fixtures/notes", "--model", "openrouter:vendor/unpriced-model"],
    ],
)
def test_setup_errors_exit_2(args: list[str], tmp_path: Path) -> None:
    os.environ["OPENROUTER_API_KEY"] = OPENROUTER_KEY  # conftest removes it again
    assert cli.main([*args, "--out", str(tmp_path)]) == cli.EXIT_SETUP


def test_abbreviated_options_are_refused() -> None:
    with pytest.raises(SystemExit):
        cli.main(["run", "--notes", "fixtures/notes", "--mod", "openrouter:x"])


# --- .env: each live switch unlocks only its own names -----------------------------------------


@pytest.fixture
def env_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    path = tmp_path / ".env"
    path.write_text(
        f"OPENROUTER_API_KEY={OPENROUTER_KEY}\nTAP_OPENROUTER_MODEL=vendor/from-env\n"
        f"GITHUB_TOKEN={GITHUB_TOKEN}\nNVD_API_KEY=nvd-LEAKTEST-key-123456\n"
        "OPENAI_BASE_URL=https://proxy.invalid/v1\n",
        encoding="utf-8",
    )
    path.chmod(0o600)
    monkeypatch.setattr(cli, "ENV_FILE", path)
    return path


def _namespace(*extra: str) -> Any:
    return cli._parser().parse_args(["run", "--notes", "fixtures/notes", *extra])  # pyright: ignore[reportPrivateUsage]


def test_a_fake_offline_run_never_opens_env(env_file: Path) -> None:
    environ: dict[str, str] = {}
    cli.resolve_settings(_namespace("--model", "fake:fixtures"), environ)
    assert environ == {}


def test_online_unlocks_only_the_api_keys(env_file: Path) -> None:
    environ: dict[str, str] = {}
    cli.resolve_settings(_namespace("--model", "fake:fixtures", "--online"), environ)
    assert sorted(environ) == ["GITHUB_TOKEN", "NVD_API_KEY"]


def test_a_live_model_unlocks_only_the_model_names(
    env_file: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    environ: dict[str, str] = {}
    settings = cli.resolve_settings(_namespace("--model", "openrouter"), environ)
    assert sorted(environ) == ["OPENROUTER_API_KEY", "TAP_OPENROUTER_MODEL"]
    assert str(settings.spec) == "openrouter:vendor/from-env"
    err = capsys.readouterr().err
    assert "OPENAI_BASE_URL" in err  # skipped and named
    assert OPENROUTER_KEY not in err
    assert GITHUB_TOKEN not in err


def test_environment_beats_env_file(env_file: Path) -> None:
    environ = {"TAP_OPENROUTER_MODEL": "vendor/from-shell"}
    settings = cli.resolve_settings(_namespace("--model", "openrouter"), environ)
    assert settings.spec.model_id == "vendor/from-shell"


# --- secrets never leak ------------------------------------------------------------------------


def _fixture_answer(request: httpx.Request) -> httpx.Response:
    """An OpenRouter stand-in that answers with the fixture claims for the prompt's section."""
    body = json.loads(request.content)
    prompt = body["messages"][-1]["content"]
    note = re.search(r'<tap_note path="([^"]*)">', prompt)
    section = re.search(r'first_line="(\d+)" last_line="(\d+)"', prompt)
    assert note is not None
    assert section is not None
    model = FixtureChatModel(notes_root=str(NOTES))
    claims = model._claims_for(  # pyright: ignore[reportPrivateUsage]
        unescape_attr(note.group(1)), int(section.group(1)), int(section.group(2))
    )
    message = {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "call_1",
                "type": "function",
                "function": {
                    "name": "ExtractionResult",
                    "arguments": json.dumps({"claims": claims}),
                },
            }
        ],
    }
    return httpx.Response(
        200,
        json={
            "id": "gen-1",
            "object": "chat.completion",
            "created": 0,
            "model": body["model"],
            "choices": [{"index": 0, "finish_reason": "tool_calls", "message": message}],
            "usage": {"prompt_tokens": 1000, "completion_tokens": 200, "cost": 0.0005},
        },
    )


def _api_from_fixtures(seen: list[httpx.Request]) -> httpx.MockTransport:
    store = ResponseStore(SOURCES)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        found = store.get(str(request.url), "sources")
        if found is None or not hasattr(found, "body"):
            return httpx.Response(404, json={"message": "Not Found"})
        return httpx.Response(found.status, content=found.body)  # type: ignore[union-attr]

    return httpx.MockTransport(handler)


def _pieces(secret: str) -> Iterator[str]:
    for start in range(len(secret) - 7):
        yield secret[start : start + 8]


def test_keys_never_appear_in_any_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    monkeypatch.setenv("OPENROUTER_API_KEY", OPENROUTER_KEY)
    monkeypatch.setenv("GITHUB_TOKEN", GITHUB_TOKEN)
    seen: list[httpx.Request] = []
    monkeypatch.setattr(
        cli,
        "OPENROUTER_HTTP_CLIENT",
        lambda: httpx.AsyncClient(transport=httpx.MockTransport(_fixture_answer)),
    )
    monkeypatch.setattr(cli, "HTTP_TRANSPORT_FACTORY", lambda: _api_from_fixtures(seen))
    code = run(
        tmp_path,
        "--online",
        model="openrouter:deepseek/deepseek-v4.1-flash",
        sources=False,
    )
    assert code == cli.EXIT_OK
    run_dir = find_run(tmp_path)
    # The token was really used, and only for GitHub.
    github = [r for r in seen if r.url.host == "api.github.com"]
    assert github
    assert all(r.headers["authorization"] == f"Bearer {GITHUB_TOKEN}" for r in github)
    assert all("authorization" not in r.headers for r in seen if r.url.host != "api.github.com")
    # Nothing the run wrote or printed holds any 8-character piece of either key.
    captured = capsys.readouterr()
    texts = {"stdout": captured.out, "stderr": captured.err, "logs": caplog.text}
    for path in sorted(run_dir.rglob("*")):
        if path.is_file():
            texts[str(path.relative_to(run_dir))] = path.read_bytes().decode("latin-1")
    assert "checkpoint.sqlite" in texts
    assert any(name.startswith("cache/") for name in texts)
    for secret in (OPENROUTER_KEY, GITHUB_TOKEN):
        for name, text in texts.items():
            leaked = [piece for piece in _pieces(secret) if piece in text]
            assert not leaked, f"{name} holds a piece of a key"
    data = report(run_dir)
    assert data["counts"]["cost_usd"] == pytest.approx(0.0005 * 9)
    assert {c["cost_source"] for c in data["calls"]} == {"reported"}
