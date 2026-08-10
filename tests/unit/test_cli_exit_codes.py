#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for friTap's CLI exit codes.

``ArgParser.error()`` prints the full help text on a usage error, which used to
end in ``self.exit(0)`` -- so no wrapper script or CI job could tell a bad
command line from a successful capture. ``docs/api/cli.md`` documents ``2`` for
"invalid arguments/configuration", so the exit code is now 2 while the help text
still goes to stdout.

The catch is that the parser is built with ``add_help=False``: ``fritap --help``
only ever "worked" as a side effect of ``error()`` exiting 0. An explicit
``-h/--help`` action now serves it, and these tests pin both halves so a future
change cannot fix one by breaking the other.

Each case runs friTap as a real subprocess, because the process exit status is
exactly what is under test. Every call is bounded by a timeout so a regression
that hangs fails loudly instead of stalling CI.
"""

from __future__ import annotations

import subprocess
import sys
import time
import uuid
from dataclasses import dataclass

import pytest

# Generous enough for a cold interpreter start plus friTap's imports (~1s
# observed), tight enough that a hang fails the test instead of the job.
_RUN_TIMEOUT_SECONDS = 60


@dataclass(frozen=True)
class CliRun:
    """The observable result of one ``python -m friTap.friTap ...`` invocation."""

    returncode: int
    stdout: str
    stderr: str
    elapsed: float = 0.0

    @property
    def shows_help(self) -> bool:
        """True when the (re-cased) argparse usage block reached stdout."""
        return "Usage:" in self.stdout or "usage:" in self.stdout

    @property
    def output(self) -> str:
        """Both streams joined, for assertions that don't care which one.

        friTap's own loggers are plain StreamHandlers (stderr) while argparse's
        help goes to stdout, so a message's stream is an implementation detail.
        """
        return self.stdout + self.stderr


def _run_cli(*argv: str, timeout: float = _RUN_TIMEOUT_SECONDS) -> CliRun:
    started = time.monotonic()
    completed = subprocess.run(
        [sys.executable, "-m", "friTap.friTap", *argv],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return CliRun(
        completed.returncode,
        completed.stdout,
        completed.stderr,
        time.monotonic() - started,
    )


# ---------------------------------------------------------------------------
# --help must keep working (add_help=False + explicit -h/--help action)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def help_run() -> CliRun:
    """``fritap --help`` executed once and shared by the help assertions."""
    return _run_cli("--help")


def test_help_exits_zero(help_run):
    assert help_run.returncode == 0


def test_help_prints_help_to_stdout(help_run):
    assert help_run.shows_help


def test_help_lists_probe_flag(help_run):
    # dev/macos_verify/verify.sh greps the help output for --probe on stdout.
    assert "--probe" in help_run.stdout


def test_short_help_flag_matches_long_form():
    run = _run_cli("-h")
    assert run.returncode == 0
    assert run.shows_help


# ---------------------------------------------------------------------------
# Usage errors must exit 2 -- and still print the help text
# ---------------------------------------------------------------------------

def test_unknown_flag_exits_two_and_prints_help():
    run = _run_cli("--bogus-flag-xyz", "com.example.app")
    assert run.returncode == 2
    assert run.shows_help
    assert "Error: unrecognized arguments: --bogus-flag-xyz" in run.stdout


def test_missing_target_exits_two_and_prints_help():
    run = _run_cli("--bogus-flag-xyz")
    assert run.returncode == 2
    assert run.shows_help


def test_full_capture_without_pcap_exits_two():
    # parser.error() from friTap's own post-parse validation, not from argparse.
    run = _run_cli("--full_capture", "-k", "keys.log", "com.example.app")
    assert run.returncode == 2
    assert run.shows_help
    assert "--full_capture requires -p" in run.stdout


# ---------------------------------------------------------------------------
# -ll / --extract-libraries must exit, not start a capture session
# ---------------------------------------------------------------------------
# ``-ll``'s help text promises "This will not start the logging process, but
# only list the libraries and exit", but ``_run_early_exit_command`` used to be
# a nested helper inside ``cli()`` whose success path was a bare ``return`` --
# returning from the helper, not from ``cli()``. So every ``-ll`` run fell
# through into a full capture session.
#
# The *absence of the banners* is the assertion that names the regression
# directly. The exit code catches it too, but only indirectly: the buggy build
# reports 0 against a bogus target, because ``os._exit(0)`` inside
# ``SSL_Logger.cleanup()`` (reached from ``cli()``'s ``finally``) pre-empts the
# ``raise Failure`` below it. Both assertions were confirmed to fail against the
# buggy helper; keep the banner check as the one that says *why*.
#
# The *hang* itself is not reproducible here either: with no such process, the
# fall-through session dies on "process not found" instead of blocking in
# ``wait_for_completion()``. ``dev/macos_verify/verify.sh`` covers that against
# a real live target.
#
# A uuid-derived target name cannot match any running process, which keeps these
# cases CI-safe: no frida-server, no root, no cooperating process needed.
_CAPTURE_BANNERS = ("Start logging", "Press Ctrl+C to stop logging")

# Well under the 30s subprocess timeout: a failed scan of a nonexistent target
# is import-time plus one frida enumerate call.
_EARLY_EXIT_BUDGET_SECONDS = 20


def _nonexistent_target() -> str:
    return f"fritap-no-such-target-{uuid.uuid4().hex}"


@pytest.fixture(scope="module")
def list_libraries_run() -> CliRun:
    """``fritap -ll <target that cannot exist>`` executed once."""
    return _run_cli("-ll", _nonexistent_target(), timeout=30)


def test_list_libraries_runs_the_inspection(list_libraries_run):
    assert "Listing loaded libraries" in list_libraries_run.output


def test_list_libraries_does_not_start_a_capture_session(list_libraries_run):
    for banner in _CAPTURE_BANNERS:
        assert banner not in list_libraries_run.output


def test_list_libraries_exits_two_on_a_failed_scan(list_libraries_run):
    assert list_libraries_run.returncode == 2


def test_list_libraries_exits_promptly(list_libraries_run):
    assert list_libraries_run.elapsed < _EARLY_EXIT_BUDGET_SECONDS


@pytest.fixture(scope="module")
def extract_libraries_run(tmp_path_factory) -> CliRun:
    """``fritap --extract-libraries <dir> <target that cannot exist>``."""
    out_dir = tmp_path_factory.mktemp("extracted")
    return _run_cli(
        "--extract-libraries", str(out_dir), _nonexistent_target(), timeout=30
    )


def test_extract_libraries_runs_the_extraction(extract_libraries_run):
    assert "Extracting TLS libraries" in extract_libraries_run.output


def test_extract_libraries_does_not_start_a_capture_session(extract_libraries_run):
    for banner in _CAPTURE_BANNERS:
        assert banner not in extract_libraries_run.output


def test_extract_libraries_exits_two_on_a_failed_scan(extract_libraries_run):
    assert extract_libraries_run.returncode == 2


def test_extract_libraries_exits_promptly(extract_libraries_run):
    assert extract_libraries_run.elapsed < _EARLY_EXIT_BUDGET_SECONDS
