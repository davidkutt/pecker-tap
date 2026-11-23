import json

import httpx
import pytest
from langchain_openai import ChatOpenAI

from pecker_tap.claims.extract import RunControl, extract_note
from pecker_tap.config import Price
from pecker_tap.cost import CostMeter
from pecker_tap.llm import (
    MissingApiKeyError,
    ModelSpec,
    ModelSpecError,
    asks_for_openrouter,
    assert_zdr,
    openrouter_model,
    parse_model_spec,
    refuse_key_as_model_id,
    resolve_openrouter_id,
)
from pecker_tap.notes.loader import parse_note

FAKE_KEY = "sk-or-v1-FAKE-LLM-TEST-not-a-real-key"


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        ("fake:fixtures", ModelSpec("fake:fixtures")),
        ("fake:invent", ModelSpec("fake:invent")),
        ("fake:inject", ModelSpec("fake:inject")),
        ("openrouter", ModelSpec("openrouter")),
        ("openrouter:vendor/model-x", ModelSpec("openrouter", "vendor/model-x")),
    ],
)
def test_model_specs(value: str, expected: ModelSpec) -> None:
    assert parse_model_spec(value) == expected


@pytest.mark.parametrize("value", ["fake", "fake:obedient", "openrouter:", "openai:gpt", ""])
def test_unknown_model_specs_are_refused(value: str) -> None:
    with pytest.raises(ModelSpecError):
        parse_model_spec(value)


def test_asks_for_openrouter_matches_what_a_gate_matches() -> None:
    assert asks_for_openrouter("openrouter")
    assert asks_for_openrouter("openrouter:x")
    assert not asks_for_openrouter("fake:fixtures")


def test_bare_openrouter_takes_the_variable_then_the_default() -> None:
    bare = ModelSpec("openrouter")
    assert resolve_openrouter_id(bare, {"TAP_OPENROUTER_MODEL": " v/m "}, "d/x") == (
        ModelSpec("openrouter", "v/m"),
        "TAP_OPENROUTER_MODEL",
    )
    assert resolve_openrouter_id(bare, {"TAP_OPENROUTER_MODEL": ""}, "d/x") == (
        ModelSpec("openrouter", "d/x"),
        "config/defaults.toml",
    )
    explicit = ModelSpec("openrouter", "a/b")
    assert resolve_openrouter_id(explicit, {"TAP_OPENROUTER_MODEL": "v/m"}, "d/x")[0] == explicit
    with pytest.raises(ModelSpecError) as raised:
        resolve_openrouter_id(bare, {"TAP_OPENROUTER_MODEL": "openrouter:v/m"}, "d/x")
    assert "openrouter:v/m" not in str(raised.value)


def test_a_model_id_that_looks_like_the_key_is_refused_without_echoing_it() -> None:
    with pytest.raises(ModelSpecError) as raised:
        refuse_key_as_model_id(
            ModelSpec("openrouter", f"vendor/{FAKE_KEY}"), {"OPENROUTER_API_KEY": FAKE_KEY}
        )
    assert FAKE_KEY not in str(raised.value)
    with pytest.raises(ModelSpecError):
        refuse_key_as_model_id(ModelSpec("openrouter", "sk-or-whatever"), {})
    refuse_key_as_model_id(ModelSpec("openrouter", "vendor/model"), {"OPENROUTER_API_KEY": "x"})


def test_missing_key_is_a_clear_error() -> None:
    with pytest.raises(MissingApiKeyError, match="OPENROUTER_API_KEY"):
        openrouter_model("vendor/model")


def test_assert_zdr_refuses_models_without_it() -> None:
    model = openrouter_model("vendor/model", api_key=FAKE_KEY)
    model.extra_body = {"provider": {"zdr": False}}
    with pytest.raises(RuntimeError, match="zdr"):
        assert_zdr(model)


def _completion(tool_args: dict[str, object]) -> dict[str, object]:
    return {
        "id": "gen-1",
        "object": "chat.completion",
        "created": 0,
        "model": "vendor/model",
        "choices": [
            {
                "index": 0,
                "finish_reason": "tool_calls",
                "message": {
                    "role": "assistant",
                    "content": None,
                    "tool_calls": [
                        {
                            "id": "call_1",
                            "type": "function",
                            "function": {
                                "name": "ExtractionResult",
                                "arguments": json.dumps(tool_args),
                            },
                        }
                    ],
                },
            }
        ],
        "usage": {
            "prompt_tokens": 900,
            "completion_tokens": 100,
            "total_tokens": 1000,
            "cost": 0.00042,
        },
    }


async def test_openrouter_request_demands_zdr_and_forces_the_tool_call() -> None:
    seen: list[dict[str, object]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.host == "openrouter.ai"
        seen.append(json.loads(request.content))
        claim = {
            "first_line": 2,
            "last_line": 2,
            "quote": "fixed in 3.8.0",
            "text": "Fixed in 3.8.0.",
            "type": "version",
            "value": {"fixed": "3.8.0"},
        }
        return httpx.Response(200, json=_completion({"claims": [claim]}))

    client = httpx.AsyncClient(transport=httpx.MockTransport(handler))
    model = openrouter_model(
        "vendor/model",
        api_key=FAKE_KEY,
        http_async_client=client,
        max_output_tokens=1234,
        providers_ignore=["SomeProvider"],
    )
    assert isinstance(model, ChatOpenAI)
    note = parse_note("a.md", "# A\nThe SDK is fixed in 3.8.0.\n")
    meter = CostMeter(0.5, Price(input_per_mtok=0.3, output_per_mtok=1.2), 1234)
    result = await extract_note(
        note, model=model, model_name="openrouter:vendor/model", meter=meter, control=RunControl()
    )
    body = seen[0]
    assert body["provider"] == {
        "require_parameters": True,
        "ignore": ["SomeProvider"],
        "zdr": True,
        "data_collection": "deny",
    }
    assert body["usage"] == {"include": True}
    assert body["max_completion_tokens"] == 1234
    assert body["tool_choice"] == {"type": "function", "function": {"name": "ExtractionResult"}}
    assert [c["quote"] for c in result.claims] == ["fixed in 3.8.0"]
    assert [(c.cost_usd, c.cost_source, c.input_tokens) for c in result.calls] == [
        (0.00042, "reported", 900)
    ]
