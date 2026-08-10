"""Shared log-capture helper for tests that assert on friTap's own loggers.

``caplog`` is unusable for those loggers: ``setup_fritap_logging`` sets
``propagate = False`` on the friTap logger hierarchy, so caplog's root handler
observes nothing — and *whether* that has happened depends on which tests ran
first, which makes the failure order-dependent and maddening to debug. Attaching
a handler directly to the logger under test sidesteps propagation entirely.

Three near-identical copies of this had accumulated across the suite; this is the
one definition.
"""

from __future__ import annotations

import logging


class LogCapture(logging.Handler):
    """Collects records straight off a logger."""

    def __init__(self, level: int = logging.DEBUG) -> None:
        super().__init__(level=level)
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def messages(self, level: int | None = None) -> list[str]:
        """Rendered messages, optionally filtered to one exact level."""
        return [r.getMessage() for r in self.records if level is None or r.levelno == level]

    @property
    def text(self) -> str:
        """All messages joined, for a quick substring assertion."""
        return "\n".join(self.messages())


def attach_log_capture(name: str) -> tuple[logging.Logger, LogCapture]:
    """Attach a :class:`LogCapture` to the named logger and return both."""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)
    capture = LogCapture()
    logger.addHandler(capture)
    return logger, capture
