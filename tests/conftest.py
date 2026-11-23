"""Shared test setup: no test may reach the network or see a real key or ``.env``."""

from __future__ import annotations

import os
from collections.abc import Generator

import pytest

from pecker_tap.netguard import allow_network, block_network

LIVE_SETTINGS = ("OPENROUTER_API_KEY", "TAP_OPENROUTER_MODEL", "GITHUB_TOKEN", "NVD_API_KEY")


@pytest.fixture(autouse=True)
def _no_network() -> Generator[None]:
    block_network()
    try:
        yield
    finally:
        allow_network()


@pytest.fixture(autouse=True)
def _no_live_settings(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> Generator[None]:
    """Hide a developer's keys, model and ``.env`` from every test; restore them afterwards.

    The CLI reads ``.env`` from the working directory, which is the checkout when pytest runs.
    Tests point it at a file that does not exist; tests of ``.env`` handling point it back at
    ``.env`` after changing into ``tmp_path``. Values the CLI copies from a test's ``.env`` into
    the environment are removed again here.
    """
    saved = {name: os.environ.pop(name, None) for name in LIVE_SETTINGS}
    monkeypatch.setattr(
        "pecker_tap.cli.ENV_FILE", tmp_path_factory.getbasetemp() / "no-such-dir" / ".env"
    )
    try:
        yield
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
