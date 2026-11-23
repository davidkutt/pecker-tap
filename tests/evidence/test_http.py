import hashlib
import json
from collections.abc import Callable
from pathlib import Path

import httpx
import pytest

from pecker_tap.config import HttpConfig, RateLimit
from pecker_tap.evidence.http import (
    Fetched,
    FetchError,
    GuardedTransport,
    HttpClient,
    RateLimiter,
    ResponseStore,
    check_url,
    is_public_address,
)

CONFIG = HttpConfig(user_agent="pecker-tap-test", max_redirects=5, max_retries=2, backoff_s=1.0)
API = "https://api.github.com/advisories/GHSA-0000-0000-0001"


def limits(_host: str) -> RateLimit:
    return RateLimit(requests=1000, per_seconds=1)


class Sleeps:
    def __init__(self) -> None:
        self.calls: list[float] = []

    async def __call__(self, seconds: float) -> None:
        self.calls.append(seconds)


def client(
    handler: Callable[[httpx.Request], httpx.Response] | None = None,
    *,
    transport: httpx.AsyncBaseTransport | None = None,
    online: bool = True,
    tmp: Path | None = None,
    sources: Path | None = None,
    sleeps: Sleeps | None = None,
    config: HttpConfig = CONFIG,
    host_headers: dict[str, dict[str, str]] | None = None,
) -> HttpClient:
    def factory() -> httpx.AsyncBaseTransport:
        if transport is not None:
            return transport
        assert handler is not None
        return httpx.MockTransport(handler)

    return HttpClient(
        config,
        limits,
        online=online,
        sources=sources,
        cache_dir=tmp / "cache" if tmp else None,
        host_headers=host_headers,
        transport_factory=factory,
        sleep=sleeps or Sleeps(),
        now=lambda: "2026-11-23T10:00:00Z",
    )


def ok(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"url": str(request.url)})


# --- URL and address checks --------------------------------------------------------------------


@pytest.mark.parametrize(
    ("url", "problem"),
    [
        ("http://api.github.com/x", "only https"),
        ("https://user:pw@api.github.com/x", "user info"),
        ("https://127.0.0.1/x", "non-public"),
        ("https://[::1]/x", "non-public"),
        ("https://10.1.2.3/x", "non-public"),
        ("https://169.254.169.254/latest/meta-data", "non-public"),
        ("ftp://files.example/x", "only https"),
        ("https:///nohost", "no host"),
    ],
)
def test_urls_outside_the_fetch_limits_are_refused(url: str, problem: str) -> None:
    reason = check_url(url)
    assert reason is not None
    assert problem in reason


def test_public_addresses() -> None:
    assert is_public_address("93.184.215.14")
    assert is_public_address("2606:2800:21f:cb07:6820:80da:af6b:8b2c")
    unspecified = "0.0.0.0"  # noqa: S104 - checked, never bound
    for address in ["127.0.0.1", "10.0.0.1", "192.168.1.1", "172.16.0.1", "169.254.1.1",
                    "100.64.0.1", unspecified, "::1", "fe80::1%eth0", "::ffff:127.0.0.1",
                    "224.0.0.1", "not-an-ip"]:  # fmt: skip
        assert not is_public_address(address), address


# --- offline -----------------------------------------------------------------------------------


async def test_offline_never_builds_a_transport_and_reports_no_source(tmp_path: Path) -> None:
    def explode() -> httpx.AsyncBaseTransport:
        raise AssertionError("no transport may be built offline")

    http = HttpClient(
        CONFIG, limits, online=False, cache_dir=tmp_path / "cache", transport_factory=explode
    )
    result = await http.get(API)
    assert isinstance(result, FetchError)
    assert result.kind == "no_source"
    assert http.network_requests == 0


async def test_sources_are_served_offline_and_copied_into_the_run_cache(tmp_path: Path) -> None:
    sources = ResponseStore(tmp_path / "sources")
    recorded = Fetched(API, API, 200, {"content-type": "application/json"}, b'{"a": 1}',
                       "2026-11-01T00:00:00Z", hashlib.sha256(b'{"a": 1}').hexdigest())  # fmt: skip
    sources.put(recorded)
    http = client(online=False, tmp=tmp_path, sources=tmp_path / "sources")
    result = await http.get(API)
    assert isinstance(result, Fetched)
    assert (result.body, result.origin, result.fetched_at) == (
        b'{"a": 1}',
        "sources",
        "2026-11-01T00:00:00Z",
    )
    cached = ResponseStore(tmp_path / "cache").get(API, "cache")
    assert isinstance(cached, Fetched)
    assert cached.body == b'{"a": 1}'


async def test_a_record_whose_body_was_changed_is_refused(tmp_path: Path) -> None:
    store = ResponseStore(tmp_path / "sources")
    store.put(Fetched(API, API, 200, {}, b"original", "t", hashlib.sha256(b"original").hexdigest()))
    next((tmp_path / "sources").glob("*.body")).write_bytes(b"tampered")
    result = await client(online=False, sources=tmp_path / "sources").get(API)
    assert isinstance(result, FetchError)
    assert result.kind == "bad_record"


# --- the guarded backend -----------------------------------------------------------------------


def resolver_to(*addresses: str):
    async def resolve(_host: str, _port: int) -> list[str]:
        return list(addresses)

    return resolve


async def test_a_hostname_resolving_to_loopback_is_refused_before_connecting() -> None:
    # The network guard of conftest raises if anything tries to connect; nothing may.
    http = client(transport=GuardedTransport(resolver_to("127.0.0.1")))
    result = await http.get("https://api.tap-fixture.example/advisories/x")
    assert isinstance(result, FetchError)
    assert result.kind == "blocked"
    assert "non-public address" in result.detail


async def test_one_private_answer_among_public_ones_is_enough_to_refuse() -> None:
    http = client(transport=GuardedTransport(resolver_to("93.184.215.14", "10.0.0.8")))
    result = await http.get("https://mixed.tap-fixture.example/")
    assert isinstance(result, FetchError)
    assert result.kind == "blocked"


class Routing(httpx.AsyncBaseTransport):
    """Serves one host from a handler and sends everything else to another transport."""

    def __init__(self, host: str, handler: Callable[[httpx.Request], httpx.Response],
                 rest: httpx.AsyncBaseTransport) -> None:  # fmt: skip
        self.host, self.mock, self.rest = host, httpx.MockTransport(handler), rest

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        if request.url.host == self.host:
            return await self.mock.handle_async_request(request)
        return await self.rest.handle_async_request(request)


async def test_a_redirect_to_a_private_address_literal_is_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://10.0.0.7/admin"})

    result = await client(handler).get(API)
    assert isinstance(result, FetchError)
    assert result.kind == "blocked"
    assert result.detail == "redirect: the URL points at a non-public address"
    assert result.redirects == ("https://10.0.0.7/admin",)


async def test_a_redirect_to_a_host_resolving_to_a_private_address_is_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(302, headers={"location": "https://internal.tap-fixture.example/"})

    transport = Routing("api.github.com", handler, GuardedTransport(resolver_to("192.168.0.10")))
    result = await client(transport=transport).get(API)
    assert isinstance(result, FetchError)
    assert result.kind == "blocked"
    assert "internal.tap-fixture.example resolves to a non-public address" in result.detail


async def test_a_redirect_to_plain_http_is_refused() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(301, headers={"location": "http://api.github.com/x"})

    result = await client(handler).get(API)
    assert isinstance(result, FetchError)
    assert (result.kind, result.detail) == ("blocked", "redirect: only https URLs are fetched")


# --- redirects, size, retries ------------------------------------------------------------------


def chain(length: int) -> Callable[[httpx.Request], httpx.Response]:
    def handler(request: httpx.Request) -> httpx.Response:
        step = int(request.url.params.get("step", "0"))
        if step < length:
            return httpx.Response(302, headers={"location": f"?step={step + 1}"})
        return httpx.Response(200, text="end")

    return handler


async def test_five_redirects_are_followed_and_recorded(tmp_path: Path) -> None:
    result = await client(chain(5), tmp=tmp_path).get(API)
    assert isinstance(result, Fetched)
    assert result.final_url == f"{API}?step=5"
    assert result.redirects == tuple(f"{API}?step={n}" for n in range(1, 6))
    record = json.loads(next((tmp_path / "cache").glob("*.json")).read_text())
    assert record["redirects"] == list(result.redirects)
    assert record["url"] == API


async def test_the_sixth_redirect_is_refused() -> None:
    result = await client(chain(6)).get(API)
    assert isinstance(result, FetchError)
    assert result.kind == "redirect_limit"
    assert len(result.redirects) == 5


async def test_size_cap_from_content_length_and_while_streaming() -> None:
    small = CONFIG.model_copy(update={"size_caps": {"default": 10}})

    def declared(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"x" * 11)

    result = await client(declared, config=small).get(API)
    assert isinstance(result, FetchError)
    assert result.kind == "too_large"

    def streamed(request: httpx.Request) -> httpx.Response:
        async def body():
            for _ in range(3):
                yield b"abcdef"

        return httpx.Response(200, content=body())  # no content-length

    result = await client(streamed, config=small).get(API)
    assert isinstance(result, FetchError)
    assert result.kind == "too_large"
    assert isinstance(await client(declared).get(API, size_cap=20), Fetched)


async def test_429_is_retried_after_retry_after() -> None:
    responses = [httpx.Response(429, headers={"retry-after": "7"}), httpx.Response(200, text="ok")]
    sleeps = Sleeps()
    result = await client(lambda _r: responses.pop(0), sleeps=sleeps).get(API)
    assert isinstance(result, Fetched)
    assert result.status == 200
    assert sleeps.calls == [7.0]


async def test_5xx_backs_off_and_the_last_answer_is_returned() -> None:
    sleeps = Sleeps()
    result = await client(lambda _r: httpx.Response(503), sleeps=sleeps).get(API)
    assert isinstance(result, Fetched)
    assert result.status == 503
    assert sleeps.calls == [1.0, 2.0]  # max_retries = 2


async def test_a_retry_after_beyond_the_cap_is_not_waited_for() -> None:
    sleeps = Sleeps()
    result = await client(
        lambda _r: httpx.Response(429, headers={"retry-after": "3600"}), sleeps=sleeps
    ).get(API)
    assert isinstance(result, Fetched)
    assert result.status == 429
    assert sleeps.calls == []


async def test_github_403_with_exhausted_rate_limit_counts_as_rate_limited() -> None:
    responses = [
        httpx.Response(403, headers={"x-ratelimit-remaining": "0", "retry-after": "1"}),
        httpx.Response(200),
    ]
    result = await client(lambda _r: responses.pop(0)).get(API)
    assert isinstance(result, Fetched)
    assert result.status == 200


async def test_network_errors_are_retried_then_unreachable() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused", request=request)

    sleeps = Sleeps()
    result = await client(handler, sleeps=sleeps).get(API)
    assert isinstance(result, FetchError)
    assert (result.kind, result.detail) == ("unreachable", "network error: ConnectError")
    assert sleeps.calls == [1.0, 2.0]


# --- keys and headers --------------------------------------------------------------------------


async def test_a_key_goes_only_to_its_host_and_never_into_the_cache(tmp_path: Path) -> None:
    seen: list[tuple[str, str | None, str]] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append((request.url.host, request.headers.get("authorization"),
                     request.headers["user-agent"]))  # fmt: skip
        if request.url.host == "api.github.com":
            return httpx.Response(302, headers={"location": "https://other.example/x"})
        return httpx.Response(200, headers={"set-cookie": "s=1", "etag": "e"}, text="ok")

    http = client(
        handler,
        tmp=tmp_path,
        host_headers={"api.github.com": {"Authorization": "Bearer ghp_FAKE_TEST_TOKEN_123"}},
    )
    result = await http.get(API)
    assert isinstance(result, Fetched)
    assert seen == [
        ("api.github.com", "Bearer ghp_FAKE_TEST_TOKEN_123", "pecker-tap-test"),
        ("other.example", None, "pecker-tap-test"),
    ]
    assert "set-cookie" not in result.headers
    assert result.headers["etag"] == "e"
    for path in (tmp_path / "cache").iterdir():
        assert b"ghp_FAKE" not in path.read_bytes()


async def test_concurrent_requests_for_one_url_fetch_it_once(tmp_path: Path) -> None:
    import asyncio

    http = client(ok, tmp=tmp_path)
    results = await asyncio.gather(*(http.get(API) for _ in range(4)))
    assert http.network_requests == 1
    assert {r.origin for r in results if isinstance(r, Fetched)} == {"network", "cache"}


# --- rate limiter ------------------------------------------------------------------------------


async def test_rate_limiter_allows_a_burst_then_spaces_requests() -> None:
    now = [0.0]
    sleeps = Sleeps()
    limiter = RateLimiter(
        lambda _h: RateLimit(requests=5, per_seconds=30, with_key=50),
        keyed_hosts=frozenset({"keyed.example"}),
        clock=lambda: now[0],
        sleep=sleeps,
    )
    for _ in range(5):
        await limiter.acquire("nvd.example")
    assert sleeps.calls == []
    await limiter.acquire("nvd.example")
    assert sleeps.calls == [pytest.approx(6.0)]  # one token per 6 seconds
    for _ in range(50):
        await limiter.acquire("keyed.example")
    assert len(sleeps.calls) == 1  # the keyed host has a bucket of 50
