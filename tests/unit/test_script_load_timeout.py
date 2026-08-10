#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for the bounded agent script load (friTap discussion #65).

Frida's ``script.load()`` blocks until the agent's top-level code returns, and
it is **not cancellable**: there is no API to abort an in-flight load. So an
agent that wedges in its top-level (an unanswered startup handshake, a
Memory.scan that never terminates, a stale/partially-built bundle) turns into
an unkillable hang in friTap with no diagnostic whatsoever — the user sees the
process sit there forever and has nothing to report.

The bound in ``FridaBackend.load_script(script, timeout=...)`` converts that
silent hang into a ``BackendScriptLoadTimeout`` carrying the elapsed time and
the agent's last reported startup stage (its "breadcrumb"), which
``SSL_Logger._load_script_bounded`` attaches and the CLI turns into actionable
hints. Because the load cannot be cancelled, the worker thread is deliberately
abandoned (daemon) rather than joined.

These tests pin four things:
  * the default (unbounded) path stays thread-hand-off free,
  * the bound actually fires quickly instead of waiting out the wedged load,
  * frida errors map to the same ``Backend*`` types on both paths, and
  * the timeout/breadcrumb/hint plumbing keeps its user-facing wording.
"""

from __future__ import annotations

import logging
import threading
import time
import types
from unittest.mock import MagicMock

import frida
import pytest

from friTap.backends.base import (
    BackendError,
    BackendScriptLoadTimeout,
    BackendTransportError,
)
from friTap.backends.frida_backend import FridaBackend
from tests.unit._log_helpers import LogCapture
from friTap.config import FriTapConfig, effective_script_load_timeout
from friTap.friTap import _process_not_responding_hints, _script_load_timeout_hints
from friTap.legacy.ssl_logger_core import SSL_Logger


# The wedged-load simulation blocks on this event instead of sleeping, so the
# abandoned daemon worker can be released in a finally block. Otherwise every
# timeout test would leave a thread parked for the full fake load duration.
_RELEASE_WEDGED_LOAD = threading.Event()


@pytest.fixture
def release_wedged_load():
    """Provide the shared release event, always setting it on teardown."""
    _RELEASE_WEDGED_LOAD.clear()
    try:
        yield _RELEASE_WEDGED_LOAD
    finally:
        _RELEASE_WEDGED_LOAD.set()


# ---------------------------------------------------------------------------
# 1 + 2: the default path must not hand off to a thread
# ---------------------------------------------------------------------------

def test_load_script_without_timeout_runs_inline_on_calling_thread():
    backend = FridaBackend()
    script = MagicMock()
    observed = []
    script.load.side_effect = lambda: observed.append(threading.current_thread())

    backend.load_script(script)

    script.load.assert_called_once_with()
    assert observed == [threading.current_thread()], (
        "the unbounded default must load on the calling thread, no worker"
    )


def test_load_script_zero_timeout_runs_inline_on_calling_thread():
    backend = FridaBackend()
    script = MagicMock()
    observed = []
    script.load.side_effect = lambda: observed.append(threading.current_thread())

    backend.load_script(script, timeout=0)

    script.load.assert_called_once_with()
    assert observed == [threading.current_thread()], (
        "timeout=0 disables the bound and must behave like the default path"
    )


# ---------------------------------------------------------------------------
# 3: the bound fires promptly instead of waiting out the wedged load
# ---------------------------------------------------------------------------

def test_load_script_times_out_well_before_the_wedged_load_finishes(
    release_wedged_load,
):
    backend = FridaBackend()
    script = MagicMock()
    # A load that would take 5 s; the bound is 0.2 s.
    script.load.side_effect = lambda: release_wedged_load.wait(5)

    started = time.monotonic()
    with pytest.raises(BackendScriptLoadTimeout) as excinfo:
        backend.load_script(script, timeout=0.2)
    wall_clock = time.monotonic() - started

    assert wall_clock < 1.0, f"bound did not fire promptly (took {wall_clock:.2f}s)"
    exc = excinfo.value
    assert exc.category == "script_load_timeout"
    assert 0.15 <= exc.elapsed_seconds < 1.0, (
        f"elapsed_seconds should be ~the bound, got {exc.elapsed_seconds}"
    )
    # The backend cannot know the agent's stage; SSL_Logger fills it in.
    assert exc.breadcrumb == ""


# ---------------------------------------------------------------------------
# 4 + 5: frida errors map identically on both paths
# ---------------------------------------------------------------------------

def test_frida_error_under_timeout_still_maps_to_backend_transport_error():
    """The worker's exception is re-raised inside the @_wrap_frida_errors frame."""
    backend = FridaBackend()
    script = MagicMock()
    script.load.side_effect = frida.TransportError("boom")

    with pytest.raises(BackendTransportError) as excinfo:
        backend.load_script(script, timeout=5.0)

    exc = excinfo.value
    assert "boom" in str(exc)
    assert isinstance(exc.original_exception, frida.TransportError)
    assert exc.category == "frida_transport"


def test_frida_error_on_inline_path_maps_the_same_way():
    backend = FridaBackend()
    script = MagicMock()
    script.load.side_effect = frida.TransportError("boom")

    with pytest.raises(BackendTransportError) as excinfo:
        backend.load_script(script)

    exc = excinfo.value
    assert "boom" in str(exc)
    assert isinstance(exc.original_exception, frida.TransportError)
    assert exc.category == "frida_transport"


# ---------------------------------------------------------------------------
# 6: non-frida failures are still tagged as friTap's fault
# ---------------------------------------------------------------------------

def test_non_frida_exception_under_timeout_is_tagged_backend_bug():
    backend = FridaBackend()
    script = MagicMock()
    script.load.side_effect = ValueError("not a frida problem")

    with pytest.raises(BackendError) as excinfo:
        backend.load_script(script, timeout=5.0)

    exc = excinfo.value
    assert exc.category == "backend_bug"
    assert isinstance(exc.original_exception, ValueError)


# ---------------------------------------------------------------------------
# 7: effective_script_load_timeout
# ---------------------------------------------------------------------------

def _config(**kwargs) -> FriTapConfig:
    kwargs.setdefault("script_load_timeout", 20.0)
    return FriTapConfig.from_legacy_params("com.example.app", **kwargs)


def test_effective_timeout_returns_configured_value_by_default():
    assert effective_script_load_timeout(_config(script_load_timeout=12.5)) == 12.5


@pytest.mark.parametrize("configured", [0, 0.0, -1.0])
def test_effective_timeout_is_none_when_non_positive(configured):
    assert effective_script_load_timeout(_config(script_load_timeout=configured)) is None


def test_effective_timeout_tripled_for_pattern_matching():
    cfg = _config(script_load_timeout=10.0, patterns="patterns.json")
    assert effective_script_load_timeout(cfg) == 30.0


def test_effective_timeout_tripled_for_library_scan():
    cfg = _config(script_load_timeout=10.0, library_scan=True)
    assert effective_script_load_timeout(cfg) == 30.0


def test_effective_timeout_tripled_for_scan_keys_region():
    cfg = _config(script_load_timeout=10.0, scan_keys_region="libssl.so")
    assert effective_script_load_timeout(cfg) == 30.0


# ---------------------------------------------------------------------------
# 8 + 9: _script_load_timeout_hints
# ---------------------------------------------------------------------------

def test_hints_name_the_agent_init_stage():
    lines = _script_load_timeout_hints(20.4, "agent-init:process-infos", 20.0)
    joined = "\n".join(lines)
    assert "before any hook was installed" in joined
    assert "agent-init:process-infos" in joined
    assert "while installing hooks" not in joined


def test_hints_name_the_install_phase_stage():
    lines = _script_load_timeout_hints(20.4, "install-phase:openssl", 20.0)
    joined = "\n".join(lines)
    assert "while installing hooks" in joined
    assert "install-phase:openssl" in joined
    assert "before any hook was installed" not in joined


def test_hints_without_breadcrumb_report_no_stage_but_still_help():
    lines = _script_load_timeout_hints(20.4, "", 20.0)
    joined = "\n".join(lines)
    assert "before any hook was installed" not in joined
    assert "while installing hooks" not in joined
    assert "never reported a startup stage" in joined
    assert len(lines) > 1


def test_hints_report_elapsed_and_the_configured_bound():
    joined = "\n".join(_script_load_timeout_hints(20.4, "", 20.0))
    assert "20.4s" in joined
    assert "20.0s" in joined


def test_hints_tolerate_an_absent_bound_and_breadcrumb():
    """effective_script_load_timeout() returns None when the user disables the
    bound, and the breadcrumb may never have arrived — neither may format-crash
    the error path itself."""
    joined = "\n".join(_script_load_timeout_hints(31.0, None, None))
    assert "31.0s" in joined
    assert "bound:" not in joined
    assert "./dev/compile_agent.sh" in joined


def test_hints_point_at_rebuild_probe_and_timeout_flag():
    joined = "\n".join(_script_load_timeout_hints(20.4, "agent-init:x", 20.0))
    assert "./dev/compile_agent.sh" in joined
    assert "--probe" in joined
    assert "--script-load-timeout" in joined


# ---------------------------------------------------------------------------
# 10: _process_not_responding_hints
# ---------------------------------------------------------------------------

def test_process_not_responding_hints_differ_between_spawn_and_attach():
    spawn_lines = _process_not_responding_hints("timed out", spawn=True)
    attach_lines = _process_not_responding_hints("timed out", spawn=False)

    assert spawn_lines and attach_lines
    assert spawn_lines != attach_lines

    spawn_joined = "\n".join(spawn_lines)
    attach_joined = "\n".join(attach_lines)
    assert "timed out" in spawn_joined and "timed out" in attach_joined
    assert "agent-injection handshake" in spawn_joined
    # Spawn advice: stop spawning, attach instead.
    assert "run WITHOUT -s" in spawn_joined
    assert "run WITHOUT -s" not in attach_joined
    # Attach advice: the process itself is wedged.
    assert "suspended, stopped in a debugger, or wedged" in attach_joined
    assert "suspended, stopped in a debugger, or wedged" not in spawn_joined
    # Shared closing advice.
    assert "backend server version matches" in spawn_joined
    assert "backend server version matches" in attach_joined


# ---------------------------------------------------------------------------
# 11 + 12: SSL_Logger._load_script_bounded
# ---------------------------------------------------------------------------

def _bounded_logger(breadcrumb="install-phase:boringssl", script_load_timeout=20.0,
                    patterns=None):
    """A bare SSL_Logger carrying only what ``_load_script_bounded`` touches."""
    obj = SSL_Logger.__new__(SSL_Logger)
    obj.logger = logging.getLogger("test.script_load_timeout")
    obj._last_hook_breadcrumb = breadcrumb
    obj._backend = MagicMock()
    obj._config = types.SimpleNamespace(
        device=types.SimpleNamespace(script_load_timeout=script_load_timeout),
        hooking=types.SimpleNamespace(
            patterns=patterns, library_scan=False, scan_keys_region=None,
        ),
    )
    return obj


def test_load_script_bounded_fills_the_breadcrumb_from_the_logger():
    obj = _bounded_logger(breadcrumb="install-phase:boringssl")
    obj._backend.load_script.side_effect = BackendScriptLoadTimeout(
        "wedged", elapsed_seconds=20.0
    )

    with pytest.raises(BackendScriptLoadTimeout) as excinfo:
        obj._load_script_bounded(MagicMock())

    assert excinfo.value.breadcrumb == "install-phase:boringssl"
    assert excinfo.value.elapsed_seconds == 20.0


def test_load_script_bounded_does_not_overwrite_an_existing_breadcrumb():
    obj = _bounded_logger(breadcrumb="agent-init:later-stage")
    obj._backend.load_script.side_effect = BackendScriptLoadTimeout(
        "wedged", elapsed_seconds=20.0, breadcrumb="install-phase:already-known"
    )

    with pytest.raises(BackendScriptLoadTimeout) as excinfo:
        obj._load_script_bounded(MagicMock())

    assert excinfo.value.breadcrumb == "install-phase:already-known"


def test_load_script_bounded_passes_the_effective_timeout_as_a_keyword():
    obj = _bounded_logger(script_load_timeout=15.0)
    script = MagicMock()

    obj._load_script_bounded(script)

    obj._backend.load_script.assert_called_once()
    call = obj._backend.load_script.call_args
    assert call.args == (script,)
    assert call.kwargs == {"timeout": 15.0}


def test_load_script_bounded_passes_the_scaled_timeout_for_scan_heavy_config():
    obj = _bounded_logger(script_load_timeout=15.0, patterns="patterns.json")

    obj._load_script_bounded(MagicMock())

    assert obj._backend.load_script.call_args.kwargs["timeout"] == 45.0


# ---------------------------------------------------------------------------
# 13: the same bound applies to plugin scripts (--custom_script and friends)
#
# A plugin's script is user-supplied JavaScript loaded through the very same
# uncancellable frida ``script.load()``. It does *not* perform friTap's blocking
# startup handshake, so it should finish faster than the main agent — which is
# exactly why the main agent's bound is a safe (generous) bound here rather than
# a tight one. Sharing it keeps one user-facing knob (--script-load-timeout),
# one opt-out (0), and one scan-heavy scaling rule.
#
# Unlike the main agent, a wedged plugin is *not* fatal: PluginLoader
# swallows-and-logs, so friTap continues without that plugin.
# ---------------------------------------------------------------------------

from friTap.plugins.loader import PluginLoader
from friTap.plugins.script_context import ScriptContext
from friTap.plugins.script_plugin import ScriptPlugin, ScriptLoadOrder


class _FakePlugin(ScriptPlugin):
    """Minimal concrete ScriptPlugin that injects a fixed one-liner."""

    def __init__(self, name="fake-plugin", source="console.log('hi');"):
        super().__init__()
        self._name = name
        self._source = source
        self.instrumented = False

    @property
    def name(self):
        return self._name

    @property
    def version(self):
        return "1.0.0"

    def get_script_source(self, context):
        self.instrumented = True
        return self._source


def _context(backend, script_load_timeout=20.0):
    return ScriptContext(
        backend=backend, process=MagicMock(), device=MagicMock(),
        runtime="qjs", event_bus=MagicMock(), backend_name="frida",
        script_load_timeout=script_load_timeout,
    )


def test_script_context_bound_defaults_to_none_so_existing_call_sites_survive():
    """The field must be optional: ScriptContext is constructed in more than one
    place and a required field would break them."""
    ctx = ScriptContext(
        backend=MagicMock(), process=MagicMock(), device=None, runtime="qjs",
        event_bus=MagicMock(), backend_name="frida",
    )
    assert ctx.script_load_timeout is None


def test_script_plugin_passes_the_context_bound_to_the_backend():
    """The regression that would silently reappear: dropping the keyword."""
    backend = MagicMock()
    backend.name = "frida"
    plugin = _FakePlugin()

    plugin.on_instrument(_context(backend, script_load_timeout=15.0))

    backend.load_script.assert_called_once()
    call = backend.load_script.call_args
    assert call.kwargs == {"timeout": 15.0}, (
        "the plugin load must be bounded by the context's resolved timeout"
    )


def test_script_plugin_passes_none_when_the_user_opted_out():
    backend = MagicMock()
    backend.name = "frida"
    plugin = _FakePlugin()

    plugin.on_instrument(_context(backend, script_load_timeout=None))

    assert backend.load_script.call_args.kwargs == {"timeout": None}


def test_script_plugin_load_is_bounded_when_the_plugin_script_wedges(
    release_wedged_load,
):
    """End to end over the real FridaBackend: a wedged plugin script surfaces as
    BackendScriptLoadTimeout instead of hanging friTap forever."""
    backend = FridaBackend()
    process = MagicMock()
    process.create_script.return_value.load.side_effect = (
        lambda: release_wedged_load.wait(5)
    )
    ctx = ScriptContext(
        backend=backend, process=process, device=None, runtime="qjs",
        event_bus=MagicMock(), backend_name="frida", script_load_timeout=0.2,
    )

    started = time.monotonic()
    with pytest.raises(BackendScriptLoadTimeout) as excinfo:
        _FakePlugin().on_instrument(ctx)
    wall_clock = time.monotonic() - started

    assert wall_clock < 1.0, f"bound did not fire promptly (took {wall_clock:.2f}s)"
    assert excinfo.value.category == "script_load_timeout"


def test_script_plugin_timeout_breadcrumb_names_the_wedged_plugin():
    """The plugin has no progress trail, so its name is the breadcrumb — it is
    the only thing that tells the user *which* script wedged."""
    backend = MagicMock()
    backend.name = "frida"
    backend.load_script.side_effect = BackendScriptLoadTimeout(
        "wedged", elapsed_seconds=20.0
    )

    with pytest.raises(BackendScriptLoadTimeout) as excinfo:
        _FakePlugin(name="my-plugin").on_instrument(_context(backend))

    assert excinfo.value.breadcrumb == "plugin:my-plugin"


def test_script_plugin_timeout_keeps_a_breadcrumb_the_backend_already_set():
    backend = MagicMock()
    backend.name = "frida"
    backend.load_script.side_effect = BackendScriptLoadTimeout(
        "wedged", elapsed_seconds=20.0, breadcrumb="already-known"
    )

    with pytest.raises(BackendScriptLoadTimeout) as excinfo:
        _FakePlugin(name="my-plugin").on_instrument(_context(backend))

    assert excinfo.value.breadcrumb == "already-known"


def test_script_plugin_does_not_track_a_script_that_timed_out():
    backend = MagicMock()
    backend.name = "frida"
    backend.load_script.side_effect = BackendScriptLoadTimeout(
        "wedged", elapsed_seconds=20.0
    )
    plugin = _FakePlugin()

    with pytest.raises(BackendScriptLoadTimeout):
        plugin.on_instrument(_context(backend))

    assert plugin._scripts == [], "a never-loaded script must not be unloaded later"


_RecordingHandler = LogCapture


def test_a_wedged_plugin_does_not_stop_the_remaining_plugins():
    """Established behaviour: PluginLoader logs the failure and carries on, so a
    bad --custom_script degrades friTap instead of killing it."""
    backend = MagicMock()
    backend.name = "frida"
    wedged = _FakePlugin(name="wedged-plugin")
    healthy = _FakePlugin(name="healthy-plugin")

    # Only the first load (the wedged plugin, registered first) times out.
    backend.load_script.side_effect = [
        BackendScriptLoadTimeout("wedged", elapsed_seconds=20.0),
        None,
    ]

    loader = PluginLoader()
    loader.register_builtin(wedged, MagicMock())
    loader.register_builtin(healthy, MagicMock())

    plugin_logger = logging.getLogger("friTap.plugins")
    handler = _RecordingHandler()
    plugin_logger.addHandler(handler)
    try:
        loader.instrument_all(_context(backend), order=ScriptLoadOrder.AFTER_MAIN)
    finally:
        plugin_logger.removeHandler(handler)

    assert healthy.instrumented, "the healthy plugin must still be instrumented"
    assert any("wedged-plugin" in m for m in handler.messages()), (
        "the log must name which plugin wedged"
    )


# ---------------------------------------------------------------------------
# 14: SSL_Logger._build_script_context resolves the bound for plugins
# ---------------------------------------------------------------------------

def _context_builder(script_load_timeout=20.0, patterns=None):
    """A bare SSL_Logger carrying only what ``_build_script_context`` touches."""
    obj = _bounded_logger(script_load_timeout=script_load_timeout, patterns=patterns)
    obj._backend.name = "frida"
    obj._event_bus = MagicMock()
    # SSL_Logger.debug / .debug_output are read-only properties over _config.
    obj._config.debug = False
    obj._config.debug_output = False
    return obj


def test_build_script_context_carries_the_effective_bound():
    ctx = _context_builder(script_load_timeout=15.0)._build_script_context(
        MagicMock(), MagicMock(), "qjs"
    )
    assert ctx.script_load_timeout == 15.0


def test_build_script_context_carries_no_bound_when_the_user_opted_out():
    ctx = _context_builder(script_load_timeout=0)._build_script_context(
        MagicMock(), MagicMock(), "qjs"
    )
    assert ctx.script_load_timeout is None


def test_build_script_context_carries_the_scaled_bound_for_scan_heavy_config():
    ctx = _context_builder(
        script_load_timeout=15.0, patterns="patterns.json"
    )._build_script_context(MagicMock(), MagicMock(), "qjs")
    assert ctx.script_load_timeout == 45.0
