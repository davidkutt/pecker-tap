import os
from pathlib import Path

import pytest

from pecker_tap.envfile import EnvFileError, EnvFileResult, load_env_file

NAMES = ("OPENROUTER_API_KEY", "TAP_OPENROUTER_MODEL")
FAKE_KEY = "sk-or-v1-FAKE-ENVFILE-not-a-real-key"


def env_file(tmp_path: Path, text: str, mode: int = 0o600) -> Path:
    path = tmp_path / ".env"
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


def test_missing_file_is_fine(tmp_path: Path) -> None:
    environ: dict[str, str] = {}
    assert load_env_file(tmp_path / ".env", NAMES, environ) == EnvFileResult()
    assert environ == {}


def test_loads_the_named_settings_only(tmp_path: Path) -> None:
    path = env_file(
        tmp_path,
        "# live-run settings\n"
        f'export OPENROUTER_API_KEY="{FAKE_KEY}"  # quoted, with export\r\n'
        "TAP_OPENROUTER_MODEL = vendor/model-x \n"
        "LANGSMITH_TRACING=true\n"
        "OPENAI_BASE_URL=https://proxy.invalid/v1\n",
    )
    environ: dict[str, str] = {}
    result = load_env_file(path, NAMES, environ)
    assert environ == {"OPENROUTER_API_KEY": FAKE_KEY, "TAP_OPENROUTER_MODEL": "vendor/model-x"}
    assert result.found
    assert result.loaded == ("OPENROUTER_API_KEY", "TAP_OPENROUTER_MODEL")
    assert result.ignored == ("LANGSMITH_TRACING", "OPENAI_BASE_URL")
    assert result.unnamed == 0


def test_environment_beats_the_file_and_empty_counts_as_unset(tmp_path: Path) -> None:
    path = env_file(
        tmp_path, f"OPENROUTER_API_KEY={FAKE_KEY}\nTAP_OPENROUTER_MODEL=vendor/from-file\n"
    )
    environ = {"OPENROUTER_API_KEY": "", "TAP_OPENROUTER_MODEL": "vendor/from-env"}
    result = load_env_file(path, NAMES, environ)
    assert environ == {"OPENROUTER_API_KEY": FAKE_KEY, "TAP_OPENROUTER_MODEL": "vendor/from-env"}
    assert result.loaded == ("OPENROUTER_API_KEY",)

    environ = {"OPENROUTER_API_KEY": "  ", "TAP_OPENROUTER_MODEL": ""}
    load_env_file(path, NAMES, environ)
    assert environ["TAP_OPENROUTER_MODEL"] == "vendor/from-file"
    assert environ["OPENROUTER_API_KEY"] == FAKE_KEY  # whitespace only is empty too


def test_empty_values_in_the_file_set_nothing(tmp_path: Path) -> None:
    path = env_file(tmp_path, "OPENROUTER_API_KEY=\nTAP_OPENROUTER_MODEL\n")
    environ: dict[str, str] = {}
    assert load_env_file(path, NAMES, environ).loaded == ()
    assert environ == {}


def test_no_interpolation(tmp_path: Path) -> None:
    path = env_file(tmp_path, "TAP_OPENROUTER_MODEL=${OTHER}/model\n")
    environ = {"OTHER": "vendor"}
    load_env_file(path, NAMES, environ)
    assert environ["TAP_OPENROUTER_MODEL"] == "${OTHER}/model"


def test_entries_without_a_plain_name_are_counted_never_named(tmp_path: Path) -> None:
    """A key pasted on a line of its own parses as a name; it must not be reported as one."""
    path = env_file(
        tmp_path,
        f"OPENROUTER_API_KEY=\n{FAKE_KEY}\nsk-or-v1-other=x\nPLAIN_FLAG\nTYPO_NAME=1\n",
    )
    environ: dict[str, str] = {}
    result = load_env_file(path, NAMES, environ)
    assert result.ignored == ("TYPO_NAME",)
    assert result.unnamed == 3  # the pasted key, the odd name and the bare PLAIN_FLAG
    assert FAKE_KEY not in repr(result)
    assert environ == {}


def test_uses_os_environ_by_default(tmp_path: Path) -> None:
    path = env_file(tmp_path, "TAP_OPENROUTER_MODEL=vendor/default-target\n")
    load_env_file(path, NAMES)
    assert os.environ["TAP_OPENROUTER_MODEL"] == "vendor/default-target"  # conftest restores it


@pytest.mark.skipif(os.name == "nt", reason="POSIX file modes")
@pytest.mark.parametrize(("mode", "too_open"), [(0o600, False), (0o640, True), (0o604, True)])
def test_flags_a_file_others_can_read(tmp_path: Path, mode: int, too_open: bool) -> None:
    path = env_file(tmp_path, "TAP_OPENROUTER_MODEL=vendor/x\n", mode)
    assert load_env_file(path, NAMES, {}).readable_by_others is too_open


def test_unreadable_encoding_is_an_error_without_content(tmp_path: Path) -> None:
    path = tmp_path / ".env"
    path.write_bytes(b"OPENROUTER_API_KEY=SECRET-\xff\xfe-VALUE\n")
    with pytest.raises(EnvFileError) as raised:
        load_env_file(path, NAMES, {})
    assert "not valid UTF-8" in str(raised.value)
    assert "SECRET" not in str(raised.value)
    assert raised.value.__context__ is None or raised.value.__suppress_context__


def test_a_directory_named_env_is_ignored(tmp_path: Path) -> None:
    (tmp_path / ".env").mkdir()
    assert not load_env_file(tmp_path / ".env", NAMES, {}).found
