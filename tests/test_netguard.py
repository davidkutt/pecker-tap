import socket

import pytest

from pecker_tap.netguard import NetworkBlockedError


def test_tcp_connect_is_blocked() -> None:
    with (
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock,
        pytest.raises(NetworkBlockedError),
    ):
        sock.connect(("192.0.2.1", 443))


def test_dns_lookup_is_blocked() -> None:
    with pytest.raises(NetworkBlockedError):
        socket.getaddrinfo("example.invalid", 443)


def test_local_socketpair_still_works() -> None:
    left, right = socket.socketpair()
    with left, right:
        left.sendall(b"ok")
        assert right.recv(2) == b"ok"
