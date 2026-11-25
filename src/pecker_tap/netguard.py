"""Block outbound network connections for offline runs (tests and fake-model self-tests)."""

from __future__ import annotations

import socket
from collections.abc import Generator
from contextlib import contextmanager
from typing import Any

_LOCAL_FAMILIES = {socket.AF_UNIX}


class NetworkBlockedError(RuntimeError):
    """Raised when code tries to open a network connection while the guard is active."""


_original_connect = socket.socket.connect
_original_connect_ex = socket.socket.connect_ex
_original_getaddrinfo = socket.getaddrinfo


def _blocked_connect(self: socket.socket, address: Any) -> None:
    if self.family in _LOCAL_FAMILIES:
        _original_connect(self, address)
        return
    msg = f"network access is blocked in offline mode (tried to connect to {address!r})"
    raise NetworkBlockedError(msg)


def _blocked_connect_ex(self: socket.socket, address: Any) -> int:
    _blocked_connect(self, address)
    return 0


def _blocked_getaddrinfo(host: Any, *args: Any, **kwargs: Any) -> Any:
    msg = f"network access is blocked in offline mode (tried to resolve {host!r})"
    raise NetworkBlockedError(msg)


def block_network() -> None:
    """Install the guard for the rest of the process."""
    socket.socket.connect = _blocked_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = _blocked_connect_ex  # type: ignore[method-assign]
    socket.getaddrinfo = _blocked_getaddrinfo


def allow_network() -> None:
    """Remove the guard."""
    socket.socket.connect = _original_connect  # type: ignore[method-assign]
    socket.socket.connect_ex = _original_connect_ex  # type: ignore[method-assign]
    socket.getaddrinfo = _original_getaddrinfo


@contextmanager
def offline() -> Generator[None]:
    """Block network access inside the `with` block."""
    block_network()
    try:
        yield
    finally:
        allow_network()
