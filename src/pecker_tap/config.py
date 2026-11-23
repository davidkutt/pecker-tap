"""Settings from ``config/defaults.toml`` (model, HTTP limits, rate limits, ATLAS pin)."""

from __future__ import annotations

import hashlib
import tomllib
from pathlib import Path
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, ValidationError

CONFIG_DIR = Path(__file__).resolve().parents[2] / "config"
DEFAULTS_FILE = CONFIG_DIR / "defaults.toml"


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class Price(_Strict):
    input_per_mtok: Annotated[float, Field(ge=0)]
    output_per_mtok: Annotated[float, Field(ge=0)]


class ModelConfig(_Strict):
    default: str
    max_output_tokens: Annotated[int, Field(gt=0)] = 4096
    temperature: float = 0.0
    timeout_s: Annotated[float, Field(gt=0)] = 120.0
    concurrency: Annotated[int, Field(gt=0)] = 4
    providers_only: tuple[str, ...] = ()
    providers_ignore: tuple[str, ...] = ()
    prices: dict[str, Price] = Field(default_factory=dict[str, Price])


class HttpConfig(_Strict):
    user_agent: str
    connect_timeout_s: Annotated[float, Field(gt=0)] = 10.0
    read_timeout_s: Annotated[float, Field(gt=0)] = 20.0
    total_timeout_s: Annotated[float, Field(gt=0)] = 90.0
    max_redirects: Annotated[int, Field(ge=0)] = 5
    max_retries: Annotated[int, Field(ge=0)] = 3
    backoff_s: Annotated[float, Field(ge=0)] = 1.0
    max_retry_after_s: Annotated[float, Field(ge=0)] = 60.0
    size_caps: dict[str, Annotated[int, Field(gt=0)]] = Field(
        default_factory=lambda: {"default": 2_000_000}
    )

    def size_cap(self, source: str) -> int:
        return self.size_caps.get(source, self.size_caps.get("default", 2_000_000))


class RateLimit(_Strict):
    requests: Annotated[int, Field(gt=0)]
    per_seconds: Annotated[float, Field(gt=0)]
    with_key: Annotated[int, Field(gt=0)] | None = None


class AtlasPin(_Strict):
    release: str
    url: str
    sha256: Annotated[str, Field(pattern=r"^[0-9a-f]{64}$")]
    collection_version: str


class Config(_Strict):
    model: ModelConfig
    http: HttpConfig
    rate_limits: dict[str, RateLimit]
    atlas: AtlasPin

    def rate_limit(self, host: str) -> RateLimit:
        return self.rate_limits.get(host) or self.rate_limits.get(
            "default", RateLimit(requests=1, per_seconds=1)
        )


class ConfigError(RuntimeError):
    pass


def load_config(path: Path = DEFAULTS_FILE) -> Config:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
        return Config.model_validate(data)
    except OSError as exc:
        msg = f"cannot read {path}: {exc.strerror or type(exc).__name__}"
        raise ConfigError(msg) from None
    except tomllib.TOMLDecodeError as exc:
        msg = f"{path} is not valid TOML: {exc}"
        raise ConfigError(msg) from None
    except ValidationError as exc:
        fields = ", ".join(
            ".".join(str(p) for p in error["loc"])
            for error in exc.errors(include_input=False, include_url=False)
        )
        msg = f"{path} has invalid settings: {fields}"
        raise ConfigError(msg) from None


def config_digest(config: Config) -> str:
    return hashlib.sha256(config.model_dump_json().encode()).hexdigest()[:16]
