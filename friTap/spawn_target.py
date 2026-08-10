#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Resolution of the spawn target argv for LOCAL spawns.

friTap's target positional is ``nargs="+"``, so the shell has already
tokenized the command line for us: ``friTap.friTap`` keeps the space-joined
string in ``config.target`` (attach-by-name / display contract) and the
original tokens in ``config.target_argv`` (issue #66).

A single token that *contains whitespace* is ambiguous, and argv alone cannot
tell the two documented readings apart:

* **command + args** -- ``fritap -s "$(which curl) https://example.com"``
  (documented in the CLI epilog, ``docs/api/cli.md`` and the troubleshooting
  guide). The shell collapses this into ONE token, so it has to be split again
  before it can be handed to ``device.spawn()``.
* **one executable whose path contains a space** -- ``fritap -s
  "/Applications/Some App.app/Contents/MacOS/Some App"`` (documented in
  ``docs/platforms/macos.md``). Splitting this shreds the path.

The tie-breaker used here is a filesystem probe of the literal token: if the
whole token names an executable file, it is that executable; otherwise it is a
command with arguments. The probe is only valid for LOCAL spawns -- for a
mobile/remote device the local filesystem says nothing about the target, and
``SessionManager`` therefore only calls this helper on the local branch.
"""

from __future__ import annotations

import logging
import os
import shutil
from typing import List, Optional, Sequence


__all__ = ["resolve_spawn_target"]


def resolve_spawn_target(
    target_argv: Optional[Sequence[str]],
    target_app: Optional[str],
    logger: Optional[logging.Logger] = None,
) -> List[str]:
    """Return the argv list to hand to ``device.spawn()`` for a LOCAL spawn.

    Args:
        target_argv: The tokens as parsed from the command line, or ``None``
            for programmatic / TUI configs that never carried argv.
        target_app: The space-joined target string, used when there is no argv.
        logger: Optional logger. When given, the chosen interpretation and the
            evidence for it are logged at INFO, and an unresolvable target is
            reported at WARNING. Omitting it keeps this function side-effect
            free and trivially unit-testable.

    Returns:
        An argv list. Never raises for an unresolvable target: the backend
        reports that with the full frida context of its own.
    """
    if not target_argv:
        # Programmatic / TUI configs that never had argv tokens. Route through
        # the same single-token resolver as the CLI rather than splitting
        # blindly: this branch was skipping the executable probe that is the
        # whole point of this module, so a programmatic spawn of
        # "/Applications/Some App.app/Contents/MacOS/Some App" still came back
        # split on spaces, and a plain Android package name (not on the local
        # PATH) drew a spurious "resolved neither as..." WARNING.
        return _resolve_single_token(target_app or "", logger)

    if len(target_argv) > 1:
        # The shell already tokenized this; there is nothing to guess.
        argv = list(target_argv)
        _log(logger, logging.INFO, "spawn target from argv tokens: argv=%r", argv)
        return argv

    return _resolve_single_token(target_argv[0], logger)


def _resolve_single_token(token: str, logger: Optional[logging.Logger]) -> List[str]:
    """Disambiguate the one-token case."""
    if not _contains_whitespace(token):
        # Unambiguous. Deliberately NOT gated on existence: a relative
        # launcher such as './app' is resolved by the backend, not by us.
        _log(logger, logging.INFO, "spawn target is a single token: argv=%r", [token])
        return [token]

    if _is_executable_file(token):
        _log(
            logger,
            logging.INFO,
            "spawn target is a single executable '%s' "
            "(executable file exists, path contains whitespace)",
            _absolute(token),
        )
        return [token]

    return _split_into_argv(token, logger, evidence=_absolute(token))


def _split_into_argv(
    token: str, logger: Optional[logging.Logger], evidence: Optional[str]
) -> List[str]:
    """Read ``token`` as "command + args" and return its argv.

    Plain :meth:`str.split` is deliberate: it collapses runs of whitespace and
    drops empty tokens, and -- unlike ``shlex.split`` -- it does not re-apply
    quote/backslash semantics to a string the user's shell has already parsed
    (``shlex.split`` turns ``C:\\Program Files\\app.exe`` into
    ``['C:Program', 'Filesapp.exe']``).
    """
    tokens = token.split()
    if evidence is None:
        _log(logger, logging.INFO, "spawn target as command + args: argv=%r", tokens)
    else:
        _log(
            logger,
            logging.INFO,
            "spawn target as command + args: argv=%r (no executable file at '%s')",
            tokens,
            evidence,
        )
    _warn_if_unresolvable(token, tokens, logger)
    return tokens


def _warn_if_unresolvable(
    token: str, tokens: List[str], logger: Optional[logging.Logger]
) -> None:
    """Warn when neither interpretation of ``token`` resolves to anything.

    Deliberately a warning and not an error: the target may still start (for
    instance when it only exists on a PATH supplied via ``-env``), and frida's
    own ``ExecutableNotFoundError`` supplies the rest. Without this warning the
    split would make the failure *harder* to read than before the split
    existed, because the error names a prefix the user never typed ('/p/My'
    for '/p/My App/app') instead of what they wrote.
    """
    if not tokens:
        return
    command = tokens[0]
    if _is_executable_file(command) or shutil.which(command) is not None:
        return
    _log(
        logger,
        logging.WARNING,
        "spawn target '%s' resolved neither as a single executable whose path "
        "contains whitespace (no executable file at '%s') nor as a command "
        "with arguments ('%s' is not an executable file and is not on PATH). "
        "Proceeding with the command + args reading argv=%r.",
        token,
        _absolute(token),
        command,
        tokens,
    )


def _is_executable_file(token: str) -> bool:
    """Does ``token`` name an executable regular file?

    ``~`` is expanded because the shell does not expand it inside quotes, and
    ``isfile`` (not ``exists``) is used so a *directory* whose name contains a
    space is never mistaken for an executable.
    """
    path = os.path.expanduser(token)
    return os.path.isfile(path) and os.access(path, os.X_OK)


def _absolute(token: str) -> str:
    """CWD-independent rendering of ``token`` for log messages.

    An already-absolute token is shown verbatim rather than normalized:
    ``abspath`` would collapse the ``//`` in an argument like
    ``https://example.com`` and print something the user never typed.
    """
    path = os.path.expanduser(token)
    return path if os.path.isabs(path) else os.path.join(os.getcwd(), path)


def _contains_whitespace(token: str) -> bool:
    return token.split() != [token]


def _log(logger: Optional[logging.Logger], level: int, message: str, *args) -> None:
    if logger is not None:
        logger.log(level, message, *args)
