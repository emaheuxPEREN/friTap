#!/usr/bin/env python3
"""Unit tests for the gated-instrumentation worker (friTap discussion #65).

These tests pin down two distinct bug classes that both made child/spawn gating
unusable:

(a) **Instrumentation running on the wrong thread.** ``on_child_added`` runs on
    Frida's device event thread and ``_handle_child_added`` runs on friTap's
    message-queue consumer thread. ``instrument()`` blocks inside
    ``script.load()`` waiting for the agent's startup handshake, so doing the
    work inline on either of those threads stalls (and historically deadlocked)
    the very thread that had to deliver the reply. Both entry points must only
    hand a ``_InstrumentRequest`` to the serial ``fritap-instrument`` worker.

(b) **A failed instrument leaving a gated process suspended forever.** A gated
    child is created suspended; if attach/load raises and nobody resumes it, the
    app hangs until the OS watchdog kills it (``0x8badf00d`` on iOS), which the
    platform reports as the app's crash rather than as friTap's failure. Every
    failure path — instrument raising, a full queue, a session already stopping
    — must still resume the pid.

Following ``tests/unit/test_crash_attribution.py``, the logger is built with
``SSL_Logger.__new__`` and only the attributes these paths touch; no device,
no session, no real Frida script.
"""

import logging
import queue
import threading
import types
from unittest.mock import MagicMock

import pytest

from friTap.legacy.ssl_logger_core import SSL_Logger, _InstrumentRequest


FAKE_DEVICE = "FAKE-DEVICE"


class FakeChild:
    """Mimics frida's ``_frida.Child`` (only the fields friTap reads)."""

    def __init__(self, pid, identifier=None):
        self.pid = pid
        self.identifier = identifier


class FakeSpawn:
    """Mimics frida's ``_frida.Spawn`` (only the fields friTap reads)."""

    def __init__(self, pid, identifier=None):
        self.pid = pid
        self.identifier = identifier


def _make_logger(instrument=None, maxsize=16, running=True,
                 target="com.example.app", mobile=True,
                 enable_child_gating=False, enable_spawn_gating=False,
                 spawn_gating_all=False):
    """A bare SSL_Logger wired with just the gating machinery.

    ``spawn_gating_all`` / ``mobile`` / ``target_app`` are read-only properties
    over ``self._config``, so they are supplied through a nested namespace.
    ``instrument`` is always stubbed: the real one creates and loads a Frida
    script.
    """
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.gated_instrumentation")
    obj.logger.setLevel(logging.DEBUG)
    obj._backend = MagicMock()
    obj.device = FAKE_DEVICE
    obj.own_message_handler = None
    obj.running = running
    obj._instrument_queue = queue.Queue(maxsize=maxsize)
    obj._instrument_stop = threading.Event()
    obj._instrument_thread = None
    obj._instrument_thread_lock = threading.Lock()
    obj.instrument = MagicMock() if instrument is None else instrument
    obj._config = types.SimpleNamespace(
        target=target,
        device=types.SimpleNamespace(
            mobile=mobile,
            enable_child_gating=enable_child_gating,
            enable_spawn_gating=enable_spawn_gating,
            spawn_gating_all=spawn_gating_all,
        ),
    )
    return obj


class ThreadRecordingInstrument:
    """``instrument`` stub that records which thread each call ran on."""

    def __init__(self, raise_on=()):
        self.threads = []
        self.calls = 0
        self.called = threading.Event()
        self._raise_on = set(raise_on)

    def __call__(self, session, handler):
        self.calls += 1
        self.threads.append(threading.current_thread())
        try:
            if self.calls in self._raise_on:
                raise RuntimeError("simulated attach/load failure")
        finally:
            self.called.set()


def _assert_never_on_caller_thread(stub, caller):
    assert caller not in stub.threads, (
        "instrument() ran inline on the calling thread "
        f"({caller.name}) — it must be handed to the fritap-instrument worker"
    )


# ----------------------------------------------------------------------
# (a) instrumentation must never run on the event / consumer thread
# ----------------------------------------------------------------------

def test_child_is_not_instrumented_inline_on_event_thread():
    """on_child_added runs on Frida's event thread: enqueue, never instrument."""
    stub = ThreadRecordingInstrument()
    obj = _make_logger(instrument=stub)
    caller = threading.current_thread()
    try:
        obj.on_child_added(FakeChild(pid=1234, identifier="com.example.app:svc"))
        # Right after the call returns nothing may have run on our thread.
        _assert_never_on_caller_thread(stub, caller)

        # Bounded wait: a reintroduced inline/deadlock regression fails in
        # seconds instead of at the 300 s pytest timeout.
        assert stub.called.wait(2), "child was never instrumented by the worker"
        _assert_never_on_caller_thread(stub, caller)
        assert stub.threads[0].name == "fritap-instrument"
    finally:
        obj._stop_instrument_thread()


def test_handle_child_added_does_not_instrument_on_consumer_thread():
    """_handle_child_added is the queue-consumer entry point: same rule."""
    stub = ThreadRecordingInstrument()
    obj = _make_logger(instrument=stub)
    caller = threading.current_thread()
    try:
        obj._handle_child_added(FakeChild(pid=4321))
        _assert_never_on_caller_thread(stub, caller)

        assert stub.called.wait(2), "queued child was never instrumented"
        _assert_never_on_caller_thread(stub, caller)
        assert stub.threads[0].name == "fritap-instrument"
    finally:
        obj._stop_instrument_thread()


# ----------------------------------------------------------------------
# spawn gating: match -> worker, no match -> resume inline
# ----------------------------------------------------------------------

def test_unrelated_spawn_is_resumed_inline_and_not_enqueued():
    obj = _make_logger(target="com.example.app", mobile=True)
    obj.on_spawn_added(FakeSpawn(pid=777, identifier="com.other.vendor.app"))

    # Resuming is cheap and non-blocking, so it happens synchronously here.
    obj._backend.resume.assert_called_once_with(FAKE_DEVICE, 777)
    assert obj._instrument_queue.empty()
    # No worker was needed for a spawn we never instrument.
    assert obj._instrument_thread is None


def test_matching_spawn_is_instrumented_by_the_worker():
    """spawn_gating_all -> the pid reaches instrument() via _backend.attach.

    Note: ``_enqueue_instrumentation`` starts the worker itself, so we cannot
    inspect the queue afterwards without racing the drain — assert on what the
    worker was handed instead.
    """
    stub = ThreadRecordingInstrument()
    obj = _make_logger(instrument=stub, spawn_gating_all=True)
    try:
        obj.on_spawn_added(FakeSpawn(pid=4242, identifier="anything.at.all"))
        assert stub.called.wait(2), "matching spawn was never instrumented"

        obj._backend.attach.assert_called_with(FAKE_DEVICE, "4242")
        obj._backend.resume.assert_called_with(FAKE_DEVICE, 4242)
    finally:
        obj._stop_instrument_thread()


# ----------------------------------------------------------------------
# (b) a failing instrument must never strand a suspended process
# ----------------------------------------------------------------------

def test_resume_is_called_even_when_instrument_raises():
    """The resume lives in a ``finally`` and must stay there.

    Resuming only on success used to strand a gated app suspended forever, which
    the platform then reports as a watchdog kill (``0x8badf00d`` on iOS) rather
    than as friTap's failure to instrument.
    """
    def boom(session, handler):
        raise RuntimeError("attach/load failed")

    obj = _make_logger(instrument=boom)
    request = _InstrumentRequest(pid=99, label="child process")

    with pytest.raises(RuntimeError):
        obj._instrument_gated_process(request)

    obj._backend.resume.assert_called_once_with(FAKE_DEVICE, 99)


def test_worker_survives_a_failing_child_and_instruments_the_next():
    """One unusable child must not end gating for every later one."""
    stub = ThreadRecordingInstrument(raise_on=(1,))
    obj = _make_logger(instrument=stub)
    try:
        obj.on_child_added(FakeChild(pid=11))
        assert stub.called.wait(2), "first child was never attempted"
        stub.called.clear()

        obj.on_child_added(FakeChild(pid=22))
        assert stub.called.wait(2), "worker died on the first failing child"

        assert stub.calls == 2
        # Both pids were resumed despite the first failure.
        resumed = [c.args for c in obj._backend.resume.call_args_list]
        assert (FAKE_DEVICE, 11) in resumed
        assert (FAKE_DEVICE, 22) in resumed
    finally:
        obj._stop_instrument_thread()


def test_full_queue_resumes_instead_of_stranding(caplog):
    """Backpressure must degrade to "uninstrumented but running", not "hung".

    ``_enqueue_instrumentation`` calls ``_start_instrument_thread()``, and a real
    worker would immediately drain the queue we are trying to keep full. Pre-set
    ``_instrument_thread`` to a non-None sentinel so ``_start_instrument_thread``
    short-circuits: no thread is ever created, so nothing consumes the queue and
    the overflow path is deterministic.
    """
    obj = _make_logger(maxsize=1)
    obj._instrument_thread = object()  # sentinel: worker "already running"
    obj._instrument_queue.put_nowait(_InstrumentRequest(pid=1, label="child process"))

    with caplog.at_level(logging.WARNING):
        obj._enqueue_instrumentation(555, "child process")

    assert "queue full" in caplog.text
    obj._backend.resume.assert_called_once_with(FAKE_DEVICE, 555)
    # The pre-filled request is untouched; only the overflow was dropped.
    assert obj._instrument_queue.qsize() == 1


def test_stop_resumes_every_request_left_in_the_queue():
    """Teardown must not drop the queue: each pending pid is still suspended.

    The worker only tests the stop event at the top of its loop and each
    iteration costs an attach plus a bounded script load, so a multi-process
    target can easily leave several requests behind when the stop flag is set.
    Dropping them strands those processes suspended until the OS watchdog kills
    them (``0x8badf00d`` on iOS) — the exact failure the finally-resume in
    ``_instrument_gated_process`` exists to prevent.

    The requests are put on the queue directly and no worker is ever started, so
    ``_stop_instrument_thread`` skips the join and the drain is the only thing
    that could possibly resume them.
    """
    obj = _make_logger()
    assert obj._instrument_thread is None, "no worker may consume the queue here"
    pending = [101, 102, 103, 104]
    for pid in pending:
        obj._instrument_queue.put_nowait(
            _InstrumentRequest(pid=pid, label="child process")
        )

    obj._stop_instrument_thread()

    resumed = [c.args for c in obj._backend.resume.call_args_list]
    assert resumed == [(FAKE_DEVICE, pid) for pid in pending], (
        "every queued pid must be resumed at teardown, in order"
    )
    assert obj._instrument_queue.empty()
    assert obj._instrument_stop.is_set()


def test_drain_keeps_going_when_a_resume_raises():
    """A drain during cleanup must never raise, and must not stop early."""
    obj = _make_logger()
    obj._backend.resume.side_effect = [RuntimeError("process already gone"), None]
    for pid in (201, 202):
        obj._instrument_queue.put_nowait(
            _InstrumentRequest(pid=pid, label="spawned process")
        )

    obj._drain_instrument_queue()  # must not raise

    resumed = [c.args for c in obj._backend.resume.call_args_list]
    assert resumed == [(FAKE_DEVICE, 201), (FAKE_DEVICE, 202)]
    assert obj._instrument_queue.empty()


def test_worker_instrumented_requests_are_not_double_resumed_by_the_drain():
    """The drain runs after the join, so it must find nothing left to do."""
    stub = ThreadRecordingInstrument()
    obj = _make_logger(instrument=stub)
    obj.on_child_added(FakeChild(pid=31))
    assert stub.called.wait(2), "child was never instrumented"

    obj._stop_instrument_thread()

    resumed = [c.args for c in obj._backend.resume.call_args_list]
    assert resumed.count((FAKE_DEVICE, 31)) == 1
    assert obj._instrument_queue.empty()


def test_resume_quietly_swallows_a_raising_resume(caplog):
    obj = _make_logger()
    obj._backend.resume.side_effect = RuntimeError("process already gone")

    with caplog.at_level(logging.WARNING):
        obj._resume_quietly(1234)  # must not raise

    assert "Failed to resume pid 1234" in caplog.text


def test_stopping_session_resumes_without_enqueueing():
    """Once teardown started, instrumenting would resurrect the joined worker."""
    obj = _make_logger(running=False)

    obj._enqueue_instrumentation(321, "child process")

    obj._backend.resume.assert_called_once_with(FAKE_DEVICE, 321)
    assert obj._instrument_queue.empty()
    assert obj._instrument_thread is None


def test_request_stop_signals_the_instrument_worker():
    obj = _make_logger()
    obj._consumer_stop = threading.Event()

    obj.request_stop()

    assert obj.running is False
    assert obj._instrument_stop.is_set()
    assert obj._consumer_stop.is_set()


# ----------------------------------------------------------------------
# eager worker startup
# ----------------------------------------------------------------------

def _stub_session_start(obj):
    """Neutralize everything start_fritap_session does besides gating setup."""
    obj.connect_live = MagicMock()
    obj._setup_live_scan = MagicMock()
    obj._start_consumer_thread = MagicMock()
    obj._session_manager = MagicMock()


def test_start_fritap_session_starts_worker_when_gating_enabled():
    obj = _make_logger(enable_child_gating=True)
    _stub_session_start(obj)
    try:
        obj.start_fritap_session()
        assert obj._instrument_thread is not None
        assert obj._instrument_thread.name == "fritap-instrument"
    finally:
        obj._stop_instrument_thread()


def test_start_fritap_session_skips_worker_without_gating():
    obj = _make_logger(enable_child_gating=False, enable_spawn_gating=False,
                       spawn_gating_all=False)
    _stub_session_start(obj)

    obj.start_fritap_session()

    assert obj._instrument_thread is None
