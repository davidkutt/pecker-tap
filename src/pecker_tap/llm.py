"""Model modes: ``fake:fixtures``, ``fake:invent``, ``fake:inject`` and ``openrouter[:<id>]``.

The fake models are LangChain chat models that answer the extraction call the same way a live
model does (a forced tool call with an ``ExtractionResult``), so the self-test runs the real
extraction path: prompt, parsing, code checks and cost accounting. They read their answers from
files next to the synthetic notes and never touch the network:

- ``fake:fixtures``: ``<note>.claims.yaml``, the claims expected for the note;
- ``fake:invent``: the same claims with quotes that are not in the note (all must be rejected);
- ``fake:inject``: the expected claims plus ``<note>.inject.yaml``, the claims a planted injection
  asks for (code-side checks must catch them).

The OpenRouter model always sends ``provider.zdr = true`` (zero data retention) and
``require_parameters = true``, so only endpoints that honour forced tool calls are used.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Literal, cast

import yaml
from langchain_core.callbacks import CallbackManagerForLLMRun
from langchain_core.language_models import BaseChatModel, LanguageModelInput
from langchain_core.messages import AIMessage, BaseMessage, HumanMessage, ToolCall
from langchain_core.outputs import ChatGeneration, ChatResult
from langchain_core.runnables import Runnable
from langchain_core.tools import BaseTool
from langchain_openai import ChatOpenAI
from pydantic import SecretStr

from pecker_tap.claims.prompt import unescape_attr
from pecker_tap.claims.schema import ExtractionResult

if TYPE_CHECKING:
    import httpx

OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"
OPENROUTER_KEY_ENV = "OPENROUTER_API_KEY"
OPENROUTER_MODEL_ENV = "TAP_OPENROUTER_MODEL"
"""Model id for a bare ``--model openrouter``. Never selects a live model on its own."""
ZDR_PROVIDER_PREFS: Mapping[str, object] = {"zdr": True, "data_collection": "deny"}
EXTRACTION_TOOL = ExtractionResult.__name__

FakeMode = Literal["fixtures", "invent", "inject"]
ModelKind = Literal["fake:fixtures", "fake:invent", "fake:inject", "openrouter"]
FAKE_KINDS: tuple[ModelKind, ...] = ("fake:fixtures", "fake:invent", "fake:inject")
INVENTED_SUFFIX = " [invented by fake:invent]"

_NOTE_TAG = re.compile(r'<tap_note path="([^"]*)">')
_SECTION_TAG = re.compile(r'<tap_section heading="[^"]*" first_line="(\d+)" last_line="(\d+)">')


class ModelSpecError(ValueError):
    """The ``--model`` value is not understood."""


@dataclass(frozen=True, slots=True)
class ModelSpec:
    kind: ModelKind
    model_id: str = ""

    @property
    def is_fake(self) -> bool:
        return self.kind != "openrouter"

    @property
    def fake_mode(self) -> FakeMode:
        if self.kind == "openrouter":
            msg = "not a fake model"
            raise ValueError(msg)
        return cast("FakeMode", self.kind.removeprefix("fake:"))

    def __str__(self) -> str:
        return f"openrouter:{self.model_id}" if self.kind == "openrouter" else self.kind


def asks_for_openrouter(value: str) -> bool:
    """``--model openrouter`` or ``openrouter:<...>``: the command line asks for a live model."""
    return value == "openrouter" or value.startswith("openrouter:")


def parse_model_spec(value: str) -> ModelSpec:
    """Parse ``--model``. A bare ``openrouter`` comes back with an empty id (resolved later)."""
    for kind in FAKE_KINDS:
        if value == kind:
            return ModelSpec(kind)
    if value == "openrouter":
        return ModelSpec("openrouter")
    prefix, _, model_id = value.partition(":")
    if prefix == "openrouter" and model_id.strip():
        return ModelSpec("openrouter", model_id.strip())
    msg = (
        f"unknown model {value!r}: use fake:fixtures, fake:invent, fake:inject, "
        f"openrouter:<model id> or openrouter (model id from {OPENROUTER_MODEL_ENV} or the default)"
    )
    raise ModelSpecError(msg)


def resolve_openrouter_id(
    spec: ModelSpec, environ: Mapping[str, str], default: str
) -> tuple[ModelSpec, str]:
    """Fill in a bare ``openrouter``: ``TAP_OPENROUTER_MODEL``, else the configured default.

    Returns the resolved spec and where the id came from (``--model``, the variable or config).
    """
    if spec.kind != "openrouter" or spec.model_id:
        return spec, "--model"
    model_id = environ.get(OPENROUTER_MODEL_ENV, "").strip()
    origin = OPENROUTER_MODEL_ENV
    if not model_id:
        model_id, origin = default, "config/defaults.toml"
    if model_id.startswith("openrouter:") or not model_id.isprintable() or " " in model_id:
        # The value is not echoed: it might be something pasted into the wrong line.
        msg = f"{OPENROUTER_MODEL_ENV} must be a bare OpenRouter model id such as vendor/model-name"
        raise ModelSpecError(msg)
    return ModelSpec("openrouter", model_id), origin


def refuse_key_as_model_id(spec: ModelSpec, environ: Mapping[str, str]) -> None:
    """A model id goes into the run record, reports and the settings digest: never the key."""
    if spec.kind != "openrouter":
        return
    key = environ.get(OPENROUTER_KEY_ENV, "").strip()
    if spec.model_id.startswith("sk-") or (len(key) >= 8 and key in spec.model_id):
        msg = (
            f"the model id looks like an API key (it starts with sk- or contains "
            f"{OPENROUTER_KEY_ENV}); check {OPENROUTER_MODEL_ENV} and --model"
        )
        raise ModelSpecError(msg)


# --- fake models -------------------------------------------------------------------------------


def _load_claims(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    data: object = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(data, list):
        msg = f"{path.name} must hold a list of claims"
        raise ValueError(msg)
    return [cast("dict[str, Any]", item) for item in cast("list[object]", data)]


class FixtureChatModel(BaseChatModel):
    """Answers each extraction call from the claim files next to the synthetic notes."""

    notes_root: str
    mode: FakeMode = "fixtures"
    cost_per_call: float = 0.0
    """Reported cost of each call (tests of the cost cap)."""

    @property
    def _llm_type(self) -> str:
        return "pecker-tap-fixtures"

    def bind_tools(
        self,
        tools: Sequence[dict[str, Any] | type | Callable[..., Any] | BaseTool],
        *,
        tool_choice: str | None = None,
        **kwargs: Any,
    ) -> Runnable[LanguageModelInput, AIMessage]:
        return self

    def _claims_for(self, note_path: str, first: int, last: int) -> list[dict[str, Any]]:
        root = Path(self.notes_root).resolve()
        note = (root / note_path).resolve()
        if not note.is_relative_to(root) or note.suffix != ".md":
            return []
        expected = _load_claims(note.with_suffix(".claims.yaml"))
        claims = [c for c in expected if first <= int(c.get("first_line", 0)) <= last]
        if self.mode == "invent":
            return [{**claim, "quote": f"{claim['quote']}{INVENTED_SUFFIX}"} for claim in claims]
        if self.mode == "inject":
            injected = _load_claims(note.with_suffix(".inject.yaml"))
            claims += [c for c in injected if first <= int(c.get("first_line", 0)) <= last]
        return claims

    def _generate(
        self,
        messages: list[BaseMessage],
        stop: list[str] | None = None,
        run_manager: CallbackManagerForLLMRun | None = None,
        **kwargs: Any,
    ) -> ChatResult:
        prompt = next(
            (str(m.content) for m in reversed(messages) if isinstance(m, HumanMessage)), ""
        )
        note_match, section_match = _NOTE_TAG.search(prompt), _SECTION_TAG.search(prompt)
        claims: list[dict[str, Any]] = []
        if note_match and section_match:
            claims = self._claims_for(
                unescape_attr(note_match.group(1)),
                int(section_match.group(1)),
                int(section_match.group(2)),
            )
        call = ToolCall(name=EXTRACTION_TOOL, args={"claims": claims}, id="call_0")
        input_tokens = max(1, sum(len(str(m.content)) for m in messages) // 4)
        output_tokens = max(1, len(str(claims)) // 4)
        reply = AIMessage(
            content="",
            tool_calls=[call],
            usage_metadata={
                "input_tokens": input_tokens,
                "output_tokens": output_tokens,
                "total_tokens": input_tokens + output_tokens,
            },
            response_metadata={"token_usage": {"cost": self.cost_per_call}},
        )
        return ChatResult(generations=[ChatGeneration(message=reply)])


# --- OpenRouter --------------------------------------------------------------------------------


class MissingApiKeyError(RuntimeError):
    pass


def openrouter_model(
    model_id: str,
    *,
    api_key: str | None = None,
    http_async_client: httpx.AsyncClient | None = None,
    timeout_s: float = 120.0,
    temperature: float | None = 0.0,
    max_output_tokens: int = 4096,
    providers_only: Sequence[str] = (),
    providers_ignore: Sequence[str] = (),
) -> ChatOpenAI:
    """An OpenRouter chat model that only routes to zero-data-retention endpoints."""
    key = api_key if api_key is not None else os.environ.get(OPENROUTER_KEY_ENV)
    if not key:
        msg = (
            f"{OPENROUTER_KEY_ENV} is not set (put it in .env, see .env.example, "
            "or read it with `read -s` / `read -s -x`)"
        )
        raise MissingApiKeyError(msg)
    provider: dict[str, object] = {"require_parameters": True}
    if providers_only:
        provider["only"] = list(providers_only)
    if providers_ignore:
        provider["ignore"] = list(providers_ignore)
    model = ChatOpenAI(
        model=model_id,
        base_url=OPENROUTER_BASE_URL,
        api_key=SecretStr(key),
        timeout=timeout_s,
        max_retries=2,
        use_responses_api=False,
        temperature=temperature,
        max_completion_tokens=max_output_tokens,
        extra_body={"provider": {**provider, **ZDR_PROVIDER_PREFS}, "usage": {"include": True}},
        http_async_client=http_async_client,
    )
    assert_zdr(model)
    return model


def assert_zdr(model: ChatOpenAI) -> None:
    """Refuse to run a live model whose requests would not demand zero data retention."""
    body = model.extra_body or {}
    provider = body.get("provider")
    if not isinstance(provider, Mapping) or provider.get("zdr") is not True:  # pyright: ignore[reportUnknownMemberType]
        msg = "OpenRouter requests must set provider.zdr = true"
        raise RuntimeError(msg)


def fake_model(spec: ModelSpec, notes_root: Path) -> FixtureChatModel:
    return FixtureChatModel(notes_root=str(notes_root), mode=spec.fake_mode)
