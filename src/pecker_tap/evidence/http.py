"""The single place for HTTP (spec, Evidence and Untrusted input; V1 brief, deliverable 5).

Every fetch goes through ``HttpClient.get``:

- **No network unless ``--online``.** Offline, responses come only from the run's own cache and
  from ``--sources`` (recorded fixtures or an earlier run's cache). A URL that isn't there gives a
  ``FetchError`` of kind ``no_source``. The network transport is never even built offline.
- **Fetch limits:** ``https`` only, no user info in URLs, at most ``max_redirects`` redirects (each
  one recorded and re-checked), a size cap per source, connect/read timeouts and a wall-clock cap
  per fetch. The guarded network backend resolves every host itself, refuses private, loopback,
  link-local and other non-public addresses, and connects to the address it checked, so a DNS
  answer can't change between the check and the connection. TLS still verifies the hostname.
- **Per-host rate limits** (token buckets from ``config/defaults.toml``) and retries with backoff
  on 429 and 5xx (``Retry-After`` honoured up to a cap).
- **Keys stay on their host.** A key is sent only in requests to the host it belongs to; a redirect
  to another host goes out without it. Keys are never cached, logged or recorded.
- **Every response is cached** in the run folder in the same format ``--sources`` reads: one
  ``<slug>.json`` record (URL, final URL, status, headers that matter, fetched_at, sha256,
  redirects) and one ``<slug>.body``. A run folder's ``cache/`` can be replayed as ``--sources``.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import socket
import time
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Literal, cast

import httpcore
import httpx

from pecker_tap.config import HttpConfig, RateLimit

FetchErrorKind = Literal[
    "no_source", "unreachable", "blocked", "too_large", "redirect_limit", "bad_record"
]
Resolver = Callable[[str, int], Awaitable[list[str]]]
Sleep = Callable[[float], Awaitable[None]]
Clock = Callable[[], float]

KEPT_HEADERS = (
    "content-type",
    "etag",
    "last-modified",
    "date",
    "retry-after",
    "location",
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "x-ratelimit-reset",
)
REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_SLUG_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


class BlockedAddressError(Exception):
    """A host resolved to an address the fetch limits don't allow (no connection was made)."""


@dataclass(frozen=True, slots=True)
class Fetched:
    url: str
    final_url: str
    status: int
    headers: Mapping[str, str]
    body: bytes
    fetched_at: str
    sha256: str
    redirects: tuple[str, ...] = ()
    origin: Literal["network", "sources", "cache"] = "network"

    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@dataclass(frozen=True, slots=True)
class FetchError:
    url: str
    kind: FetchErrorKind
    detail: str = ""
    redirects: tuple[str, ...] = ()


FetchResult = Fetched | FetchError


# --- address checks ----------------------------------------------------------------------------


def is_public_address(address: str) -> bool:
    """True only for globally routable unicast addresses."""
    try:
        ip = ipaddress.ip_address(address.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not (
        ip.is_multicast or ip.is_loopback or ip.is_link_local or ip.is_private or ip.is_reserved
    )


def _ip_literal(host: str) -> str | None:
    try:
        return str(ipaddress.ip_address(host.strip("[]")))
    except ValueError:
        return None


def check_url(url: str) -> str | None:
    """Why ``url`` may not be fetched, or ``None`` if the fetch limits allow it."""
    try:
        parsed = httpx.URL(url)
    except (httpx.InvalidURL, TypeError):
        return "not a valid URL"
    if parsed.scheme != "https":
        return "only https URLs are fetched"
    if not parsed.host:
        return "the URL has no host"
    if parsed.userinfo:
        return "URLs with user info are not fetched"
    literal = _ip_literal(parsed.host)
    if literal is not None and not is_public_address(literal):
        return "the URL points at a non-public address"
    return None


async def system_resolver(host: str, port: int) -> list[str]:
    loop = asyncio.get_running_loop()
    infos = await loop.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return list(dict.fromkeys(str(info[4][0]) for info in infos))


class GuardedBackend(httpcore.AsyncNetworkBackend):
    """Resolves the host, refuses non-public addresses, connects to the checked address."""

    def __init__(self, resolver: Resolver, inner: httpcore.AsyncNetworkBackend | None = None):
        self._resolver = resolver
        # httpcore defines AnyIOBackend conditionally, which hides its base class from Pyright.
        default = cast("httpcore.AsyncNetworkBackend", httpcore.AnyIOBackend())
        self._inner: httpcore.AsyncNetworkBackend = inner or default

    async def connect_tcp(
        self,
        host: str,
        port: int,
        timeout: float | None = None,  # noqa: ASYNC109 - httpcore's interface
        local_address: str | None = None,
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        literal = _ip_literal(host)
        addresses = [literal] if literal is not None else await self._resolver(host, port)
        if not addresses:
            msg = f"{host} did not resolve"
            raise BlockedAddressError(msg)
        if not all(is_public_address(address) for address in addresses):
            msg = f"{host} resolves to a non-public address"
            raise BlockedAddressError(msg)
        last: Exception | None = None
        for address in addresses:
            try:
                return await self._inner.connect_tcp(
                    address, port, timeout, local_address, socket_options
                )
            except (OSError, httpcore.ConnectError, httpcore.ConnectTimeout) as exc:
                last = exc
        if last is None:  # pragma: no cover - addresses is never empty here
            raise BlockedAddressError(host)
        raise last

    async def connect_unix_socket(
        self,
        path: str,
        timeout: float | None = None,  # noqa: ASYNC109 - httpcore's interface
        socket_options: Iterable[httpcore.SOCKET_OPTION] | None = None,
    ) -> httpcore.AsyncNetworkStream:
        msg = "unix sockets are not fetched"
        raise BlockedAddressError(msg)

    async def sleep(self, seconds: float) -> None:
        await self._inner.sleep(seconds)


class GuardedTransport(httpx.AsyncHTTPTransport):
    """httpx transport over the guarded backend. No proxies from the environment."""

    def __init__(self, resolver: Resolver = system_resolver) -> None:
        super().__init__(trust_env=False)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=httpx.create_ssl_context(trust_env=True),
            max_connections=10,
            network_backend=GuardedBackend(resolver),
        )


# --- rate limits -------------------------------------------------------------------------------


@dataclass
class _Bucket:
    capacity: float
    rate: float
    tokens: float
    updated: float


@dataclass
class RateLimiter:
    """Token bucket per host: ``requests`` per ``per_seconds``, bursts up to ``requests``."""

    limits: Callable[[str], RateLimit]
    keyed_hosts: frozenset[str] = frozenset()
    clock: Clock = time.monotonic
    sleep: Sleep = asyncio.sleep
    _buckets: dict[str, _Bucket] = field(default_factory=dict[str, _Bucket])
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    def _bucket(self, host: str) -> _Bucket:
        bucket = self._buckets.get(host)
        if bucket is None:
            limit = self.limits(host)
            requests = limit.with_key if host in self.keyed_hosts and limit.with_key else None
            capacity = float(requests or limit.requests)
            bucket = _Bucket(capacity, capacity / limit.per_seconds, capacity, self.clock())
            self._buckets[host] = bucket
        return bucket

    async def acquire(self, host: str) -> None:
        async with self._lock:
            bucket = self._bucket(host)
            now = self.clock()
            bucket.tokens = min(
                bucket.capacity, bucket.tokens + (now - bucket.updated) * bucket.rate
            )
            bucket.updated = now
            wait = 0.0 if bucket.tokens >= 1 else (1 - bucket.tokens) / bucket.rate
            bucket.tokens -= 1
        if wait > 0:
            await self.sleep(wait)


# --- the recorded-response store ---------------------------------------------------------------


def slug_for(url: str) -> str:
    parsed = httpx.URL(url)
    readable = _SLUG_UNSAFE.sub("_", f"{parsed.host}{parsed.raw_path.decode('ascii', 'replace')}")
    digest = hashlib.sha256(url.encode()).hexdigest()[:10]
    return f"{readable.strip('_')[:80]}-{digest}"


class ResponseStore:
    """A folder of recorded responses (fixtures, a run cache), indexed by URL."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self._index: dict[str, Path] | None = None

    def _load_index(self) -> dict[str, Path]:
        if self._index is None:
            index: dict[str, Path] = {}
            if self.root.is_dir():
                for path in sorted(self.root.glob("*.json")):
                    try:
                        record: object = json.loads(path.read_text(encoding="utf-8"))
                    except (OSError, ValueError):
                        continue
                    if isinstance(record, dict) and isinstance(record.get("url"), str):  # pyright: ignore[reportUnknownMemberType]
                        index.setdefault(str(record["url"]), path)  # pyright: ignore[reportUnknownArgumentType]
            self._index = index
        return self._index

    def __contains__(self, url: str) -> bool:
        return url in self._load_index()

    def get(self, url: str, origin: Literal["sources", "cache"]) -> FetchResult | None:
        path = self._load_index().get(url)
        if path is None:
            return None
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
            body = (self.root / Path(str(record["body_file"])).name).read_bytes()
            sha = hashlib.sha256(body).hexdigest()
            if sha != record["sha256"]:
                return FetchError(url, "bad_record", f"{path.name}: sha256 does not match the body")
            return Fetched(
                url=url,
                final_url=str(record.get("final_url") or url),
                status=int(record["status"]),
                headers={str(k): str(v) for k, v in dict(record.get("headers") or {}).items()},
                body=body,
                fetched_at=str(record["fetched_at"]),
                sha256=sha,
                redirects=tuple(str(item) for item in record.get("redirects") or ()),
                origin=origin,
            )
        except (OSError, ValueError, KeyError, TypeError):
            return FetchError(url, "bad_record", f"{path.name} is not a valid record")

    def put(self, response: Fetched) -> None:
        self.root.mkdir(parents=True, exist_ok=True)
        slug = slug_for(response.url)
        (self.root / f"{slug}.body").write_bytes(response.body)
        record = {
            "url": response.url,
            "final_url": response.final_url,
            "status": response.status,
            "headers": dict(response.headers),
            "fetched_at": response.fetched_at,
            "sha256": response.sha256,
            "body_file": f"{slug}.body",
            "redirects": list(response.redirects),
        }
        (self.root / f"{slug}.json").write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        if self._index is not None:
            self._index[response.url] = self.root / f"{slug}.json"


# --- the client --------------------------------------------------------------------------------


def _utc_now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _retry_after(value: str | None, cap: float) -> float | None:
    """Seconds from a ``Retry-After`` header (seconds or HTTP date); ``None`` if absent."""
    if not value:
        return None
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return cap
    return max(0.0, (when - datetime.now(UTC)).total_seconds())


def _rate_limited(response: httpx.Response) -> bool:
    if response.status_code in RETRY_STATUSES:
        return True
    return response.status_code == 403 and response.headers.get("x-ratelimit-remaining") == "0"


class HttpClient:
    def __init__(
        self,
        config: HttpConfig,
        rate_limits: Callable[[str], RateLimit],
        *,
        online: bool,
        sources: Path | None = None,
        cache_dir: Path | None = None,
        host_headers: Mapping[str, Mapping[str, str]] | None = None,
        transport_factory: Callable[[], httpx.AsyncBaseTransport] | None = None,
        sleep: Sleep = asyncio.sleep,
        clock: Clock = time.monotonic,
        now: Callable[[], str] = _utc_now,
    ) -> None:
        self.config = config
        self.online = online
        self.sources = ResponseStore(sources) if sources is not None else None
        self.cache = ResponseStore(cache_dir) if cache_dir is not None else None
        self._host_headers = {host: dict(headers) for host, headers in (host_headers or {}).items()}
        self._transport_factory = transport_factory or GuardedTransport
        self._client: httpx.AsyncClient | None = None
        self._sleep = sleep
        self._clock = clock
        self._now = now
        self._limiter = RateLimiter(
            rate_limits, frozenset(self._host_headers), clock=clock, sleep=sleep
        )
        self._url_locks: dict[str, asyncio.Lock] = {}
        self.network_requests = 0

    @property
    def sources_dir(self) -> Path | None:
        return self.sources.root if self.sources is not None else None

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def _http(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(
                transport=self._transport_factory(),
                follow_redirects=False,
                trust_env=False,
                timeout=httpx.Timeout(
                    self.config.read_timeout_s, connect=self.config.connect_timeout_s
                ),
                headers={"User-Agent": self.config.user_agent},
            )
        return self._client

    async def get(
        self, url: str, *, accept: str = "application/json", size_cap: int | None = None
    ) -> FetchResult:
        """Fetch ``url`` within the fetch limits; see the module docstring for the order."""
        reason = check_url(url)
        if reason is not None:
            return FetchError(url, "blocked", reason)
        lock = self._url_locks.setdefault(url, asyncio.Lock())
        async with lock:
            for store, origin in ((self.cache, "cache"), (self.sources, "sources")):
                if store is not None:
                    found = store.get(url, origin)  # type: ignore[arg-type]
                    if found is not None:
                        if isinstance(found, Fetched) and origin == "sources" and self.cache:
                            self.cache.put(found)
                        return found
            if not self.online:
                return FetchError(url, "no_source", "not in --sources and the run is offline")
            cap = size_cap or self.config.size_cap("default")
            try:
                async with asyncio.timeout(self.config.total_timeout_s):
                    result = await self._fetch(url, accept, cap)
            except TimeoutError:
                result = FetchError(url, "unreachable", "the fetch took too long")
            if isinstance(result, Fetched) and self.cache is not None:
                self.cache.put(result)
            return result

    async def _fetch(self, url: str, accept: str, cap: int) -> FetchResult:
        redirects: list[str] = []
        current = url
        while True:
            outcome = await self._fetch_one(current, accept, cap, redirects)
            if isinstance(outcome, FetchError):
                return outcome
            status, headers, body = outcome
            location = headers.get("location")
            if status in REDIRECT_STATUSES and location:
                if len(redirects) >= self.config.max_redirects:
                    detail = f"more than {self.config.max_redirects} redirects"
                    return FetchError(url, "redirect_limit", detail, tuple(redirects))
                target = str(httpx.URL(current).join(location))
                reason = check_url(target)
                redirects.append(target)
                if reason is not None:
                    return FetchError(url, "blocked", f"redirect: {reason}", tuple(redirects))
                current = target
                continue
            return Fetched(
                url=url,
                final_url=current,
                status=status,
                headers=headers,
                body=body,
                fetched_at=self._now(),
                sha256=hashlib.sha256(body).hexdigest(),
                redirects=tuple(redirects),
            )

    async def _fetch_one(
        self, url: str, accept: str, cap: int, redirects: list[str]
    ) -> tuple[int, dict[str, str], bytes] | FetchError:
        host = httpx.URL(url).host
        headers = {"Accept": accept, **self._host_headers.get(host, {})}
        attempts = self.config.max_retries + 1
        for attempt in range(attempts):
            await self._limiter.acquire(host)
            self.network_requests += 1
            try:
                async with self._http().stream("GET", url, headers=headers) as response:
                    declared = response.headers.get("content-length", "")
                    if declared.isdigit() and int(declared) > cap:
                        return FetchError(
                            url, "too_large", f"more than {cap} bytes", tuple(redirects)
                        )
                    chunks: list[bytes] = []
                    size = 0
                    async for chunk in response.aiter_bytes():  # decoded: caps a gzip bomb too
                        size += len(chunk)
                        if size > cap:
                            return FetchError(
                                url, "too_large", f"more than {cap} bytes", tuple(redirects)
                            )
                        chunks.append(chunk)
                    kept = {
                        name: response.headers[name]
                        for name in KEPT_HEADERS
                        if name in response.headers
                    }
                    if _rate_limited(response) and attempt + 1 < attempts:
                        wait = _retry_after(
                            response.headers.get("retry-after"), self.config.max_retry_after_s
                        )
                        if wait is None:
                            wait = self.config.backoff_s * 2**attempt
                        if wait <= self.config.max_retry_after_s:
                            await self._sleep(wait)
                            continue
                    return response.status_code, kept, b"".join(chunks)
            except BlockedAddressError as exc:
                return FetchError(url, "blocked", str(exc), tuple(redirects))
            except httpx.TransportError as exc:
                if attempt + 1 < attempts:
                    await self._sleep(self.config.backoff_s * 2**attempt)
                    continue
                detail = f"network error: {type(exc).__name__}"
                return FetchError(url, "unreachable", detail, tuple(redirects))
        return FetchError(url, "unreachable", "no attempts left", tuple(redirects))
