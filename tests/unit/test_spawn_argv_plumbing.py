#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Plumbing tests for spawn argv resolution (issue #66 follow-up + #66 bug).

The CLI target positional is nargs="+", so `fritap -s wine /p/My Game/app.exe`
parses into argv tokens. friTap keeps `config.target` as the space-joined string
(for attach-by-name / display) but carries the original tokens in
`config.target_argv` so spawn passes the real argv to device.spawn() — instead
of re-splitting the joined string on spaces and shredding a path that contains
a space.

A *single* argv token containing whitespace is ambiguous, though: the shell
collapses `"$(which curl) https://example.com"` into one token too. friTap's
`resolve_spawn_target` disambiguates with a local filesystem probe. These tests
exercise the real helper (no duplicated logic) without a frida-server.
"""

from __future__ import annotations

import logging
import os
import stat

from friTap.config import FriTapConfig
from friTap.spawn_target import resolve_spawn_target
from tests.unit._log_helpers import attach_log_capture


SPACED_ARGV = ["wine", "/home/u/.wine/drive_c/Program Files/My Game/app.exe"]
SPACED_JOINED = " ".join(SPACED_ARGV)


def _select_spawn_target(cfg: FriTapConfig, logger: logging.Logger | None = None):
    """Call the real production helper the way SessionManager does."""
    return resolve_spawn_target(cfg.target_argv, cfg.target, logger)


_recording_logger = attach_log_capture


def _make_executable(path) -> str:
    path.write_text("#!/bin/sh\nexit 0\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


# --------------------------------------------------------------------------
# existing contract (issue #66): multi-token argv is preserved verbatim
# --------------------------------------------------------------------------


def test_from_legacy_params_keeps_target_string_and_argv_list():
    cfg = FriTapConfig.from_legacy_params(
        app=SPACED_JOINED, spawn_argv=SPACED_ARGV, spawn=True
    )
    # target stays a single string (attach-by-name / display contract)
    assert cfg.target == SPACED_JOINED
    # argv tokens preserved for spawn
    assert cfg.target_argv == SPACED_ARGV


def test_spawn_target_selection_preserves_spaced_path():
    cfg = FriTapConfig.from_legacy_params(
        app=SPACED_JOINED, spawn_argv=SPACED_ARGV, spawn=True
    )
    # The spaced path must remain a SINGLE token, not be split on its spaces.
    assert _select_spawn_target(cfg) == SPACED_ARGV


def test_missing_argv_falls_back_to_split():
    # Programmatic / TUI configs supply no argv → old split behavior preserved
    # (no regression for callers that never had argv tokens).
    cfg = FriTapConfig.from_legacy_params(app=SPACED_JOINED, spawn=True)
    assert cfg.target_argv is None
    assert _select_spawn_target(cfg) == SPACED_JOINED.split(" ")


def test_single_token_spawn_unaffected():
    cfg = FriTapConfig.from_legacy_params(
        app="./app", spawn_argv=["./app"], spawn=True
    )
    # Relative and non-existent: resolution must gate on whitespace, never on
    # existence, or the backend never gets the chance to resolve it.
    assert _select_spawn_target(cfg) == ["./app"]


# --------------------------------------------------------------------------
# the ambiguous one-token case
# --------------------------------------------------------------------------


def test_single_token_spaced_path_that_exists_is_kept_whole(tmp_path):
    app_dir = tmp_path / "Some App.app"
    app_dir.mkdir()
    exe = _make_executable(app_dir / "Some App")

    cfg = FriTapConfig.from_legacy_params(app=exe, spawn_argv=[exe], spawn=True)
    assert _select_spawn_target(cfg) == [exe]


def test_single_token_spaced_path_that_does_not_exist_is_split():
    target = "/nonexistent/My App/app.exe --flag"
    cfg = FriTapConfig.from_legacy_params(
        app=target, spawn_argv=[target], spawn=True
    )
    assert _select_spawn_target(cfg) == [
        "/nonexistent/My",
        "App/app.exe",
        "--flag",
    ]


def test_documented_command_plus_args_shape_is_split(tmp_path):
    # The shape from the CLI epilog / docs: `-s "$(which curl) https://…"`.
    # The shell collapses it into ONE token containing whitespace.
    exe = _make_executable(tmp_path / "curl")
    target = f"{exe} https://example.com"

    cfg = FriTapConfig.from_legacy_params(
        app=target, spawn_argv=[target], spawn=True
    )
    assert _select_spawn_target(cfg) == [exe, "https://example.com"]


def test_spaced_directory_is_not_treated_as_executable(tmp_path):
    # isfile, not exists: a *directory* with a space must still be split.
    spaced_dir = tmp_path / "My App"
    spaced_dir.mkdir()

    assert resolve_spawn_target([str(spaced_dir)], str(spaced_dir)) == [
        str(tmp_path / "My"),
        "App",
    ]


def test_double_space_produces_no_empty_tokens():
    # str.split() with no argument collapses runs of whitespace, unlike the
    # old split(" ") which produced an empty token in the middle.
    assert resolve_spawn_target(["a  b"], "a  b") == ["a", "b"]
    assert resolve_spawn_target(None, "a  b") == ["a", "b"]


def test_tilde_is_expanded_for_the_probe(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    exe_dir = tmp_path / "My Apps"
    exe_dir.mkdir()
    _make_executable(exe_dir / "app")

    token = "~/My Apps/app"
    # The literal token (with ~) is returned, so the backend sees exactly what
    # the user typed, but the probe recognised it as one executable.
    assert resolve_spawn_target([token], token) == [token]


def test_backslash_path_is_not_reparsed_by_shlex():
    # shlex.split(posix=True) would eat the backslashes here; str.split must not.
    token = r"C:\Program Files\App\app.exe --verbose"
    assert resolve_spawn_target([token], token) == [
        r"C:\Program",
        r"Files\App\app.exe",
        "--verbose",
    ]


# --------------------------------------------------------------------------
# diagnostics
# --------------------------------------------------------------------------


def test_logs_single_executable_interpretation_with_absolute_path(tmp_path):
    exe = _make_executable(tmp_path / "Some App")
    logger, recorder = _recording_logger("test.spawn_target.single")
    try:
        assert resolve_spawn_target([exe], exe, logger) == [exe]
    finally:
        logger.removeHandler(recorder)

    info = " ".join(recorder.messages(logging.INFO))
    assert "single executable" in info
    assert os.path.abspath(exe) in info
    assert not recorder.messages(logging.WARNING)


def test_logs_command_plus_args_interpretation(tmp_path):
    exe = _make_executable(tmp_path / "curl")
    target = f"{exe} https://example.com"
    logger, recorder = _recording_logger("test.spawn_target.split")
    try:
        assert resolve_spawn_target([target], target, logger) == [
            exe,
            "https://example.com",
        ]
    finally:
        logger.removeHandler(recorder)

    info = " ".join(recorder.messages(logging.INFO))
    assert "command + args" in info
    # argv[0] resolves, so no warning is due.
    assert not recorder.messages(logging.WARNING)


def test_warns_when_neither_interpretation_resolves():
    target = "/nonexistent/My App/app.exe"
    logger, recorder = _recording_logger("test.spawn_target.warn")
    try:
        # Still proceeds with the split — a warning, never an exception.
        assert resolve_spawn_target([target], target, logger) == [
            "/nonexistent/My",
            "App/app.exe",
        ]
    finally:
        logger.removeHandler(recorder)

    warnings = recorder.messages(logging.WARNING)
    assert len(warnings) == 1
    warning = warnings[0]
    # Names BOTH candidate interpretations and that neither resolved.
    assert target in warning
    assert "/nonexistent/My" in warning
    assert "not on PATH" in warning


def test_no_logging_without_a_logger():
    # Usable (and side-effect free) with the default logger=None.
    assert resolve_spawn_target(["/nope/My App/x"], "/nope/My App/x") == [
        "/nope/My",
        "App/x",
    ]


def test_multi_token_argv_is_logged_as_verbatim_argv():
    logger, recorder = _recording_logger("test.spawn_target.multi")
    try:
        assert resolve_spawn_target(SPACED_ARGV, SPACED_JOINED, logger) == SPACED_ARGV
    finally:
        logger.removeHandler(recorder)

    assert "argv tokens" in " ".join(recorder.messages(logging.INFO))
    assert not recorder.messages(logging.WARNING)
