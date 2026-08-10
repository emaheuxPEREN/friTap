"""Guards against two documentation defects about friTap's output stream.

friTap writes **everything** to stderr: ``setup_fritap_logging`` builds both the
main and the "no prefix" logger with a bare ``logging.StreamHandler()``, which
defaults to ``sys.stderr`` (friTap/fritap_utility.py), and nothing in the capture
path prints to stdout. Measured: ``fritap -ll <pid>`` emits **0 bytes** on stdout.

Two consequences the docs used to get wrong:

1. They claimed that piping friTap into ``head``/``grep`` caused an early
   ``EPIPE`` that "wedges friTap's signal handling". That is mechanically
   impossible -- friTap never writes to the pipe, so the reader never closes it
   and no ``EPIPE`` is ever raised. (CPython also sets SIGPIPE to ``SIG_IGN`` at
   startup, so a broken pipe surfaces as ``BrokenPipeError``, and
   ``logging.Handler.emit`` swallows handler errors without propagating.)
2. Example commands piped ``fritap ... | grep`` with no ``2>&1``, so they
   filtered an empty stream and showed the reader nothing.
"""

from __future__ import annotations

import os
import re

_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# "an early EPIPE wedges friTap's signal handling", and variants.
#
# Matched against the whole file with newlines collapsed, NOT line by line:
# this prose is hard-wrapped at ~80 columns, so the claim would routinely
# straddle two physical lines and a per-line scan would miss it. "broken pipe"
# is included because that is the natural rewording of EPIPE.
_EPIPE_MISDIAGNOSIS = re.compile(
    r"(EPIPE|broken pipe).{0,120}(wedge|signal handling|hang)"
    r"|(wedge|hang).{0,120}(EPIPE|broken pipe)",
    re.IGNORECASE,
)

# A fritap invocation piped into a filter without redirecting stderr first.
_UNREDIRECTED_PIPE = re.compile(r"^\s*(?:sudo\s+)?fritap\s+[^|]*\|\s*(?:grep|head|wc)\b")

# Command substitutions are stripped before matching: a pipe inside `$(...)`
# belongs to the inner command, not to friTap. `-p "$(pgrep -f app.exe | head -1)"`
# must NOT be flagged -- adding 2>&1 there would turn pgrep's error output into
# the PID.
_COMMAND_SUBSTITUTION = re.compile(r"\$\([^)]*\)")


def _outer_command(line: str) -> str:
    return _COMMAND_SUBSTITUTION.sub("SUBST", line)


def _doc_files():
    for root in ("docs", "dev"):
        for dirpath, _dirnames, filenames in os.walk(os.path.join(_REPO_ROOT, root)):
            for name in filenames:
                if name.endswith((".md", ".sh")):
                    yield os.path.join(dirpath, name)


def test_no_doc_repeats_the_epipe_misdiagnosis():
    offenders = []
    for path in _doc_files():
        with open(path, encoding="utf-8", errors="ignore") as fh:
            text = fh.read()
        # Collapse newlines so a claim hard-wrapped across lines still matches.
        flattened = re.sub(r"\s+", " ", text)
        match = _EPIPE_MISDIAGNOSIS.search(flattened)
        if match:
            offenders.append(f"{os.path.relpath(path, _REPO_ROOT)}: ...{match.group(0)}...")

    assert not offenders, (
        "friTap writes only to stderr during a capture, so no EPIPE can occur "
        "when its stdout is piped. Stale claim(s) found:\n  " + "\n  ".join(offenders)
    )


def test_the_epipe_guard_actually_catches_reintroductions():
    """The guard is only worth having if it survives rewording and line wrapping."""
    flatten = lambda s: re.sub(r"\s+", " ", s)  # noqa: E731

    caught = [
        "An early EPIPE wedges friTap's signal handling.",
        # Hard-wrapped across two lines, as this prose actually is:
        "Closing friTap's stdout early raises `EPIPE` inside it and\nwedges its signal handling for minutes.",
        # Reworded without the literal token:
        "A broken pipe wedges friTap's signal handling.",
        "friTap's signal handling will hang after an EPIPE.",
    ]
    for claim in caught:
        assert _EPIPE_MISDIAGNOSIS.search(flatten(claim)), f"guard missed: {claim!r}"

    # Must not fire on legitimate, unrelated prose.
    for benign in [
        "friTap writes to stderr, so add 2>&1 to pipe it.",
        "A wedged detach thread can block interpreter shutdown.",
        "The MessagePipeline handles broken output sinks.",
    ]:
        assert not _EPIPE_MISDIAGNOSIS.search(flatten(benign)), f"false positive: {benign!r}"


def test_piped_examples_redirect_stderr():
    offenders = []
    for path in _doc_files():
        if not path.endswith(".md"):
            continue
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for lineno, line in enumerate(fh, 1):
                if _UNREDIRECTED_PIPE.match(_outer_command(line)) and "2>&1" not in line:
                    offenders.append(f"{os.path.relpath(path, _REPO_ROOT)}:{lineno}: {line.strip()}")

    assert not offenders, (
        "friTap logs to stderr, so these piped examples filter an empty stream "
        "and show nothing. Add `2>&1` before the pipe, or use --debug-log:\n  "
        + "\n  ".join(offenders)
    )
