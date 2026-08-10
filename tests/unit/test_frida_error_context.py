#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Unit tests for the diagnostic context attached to backend errors.

``_wrap_frida_errors`` translates frida exceptions into Backend* exceptions and
attaches a ``BackendErrorContext``. Which diagnostics it may sample depends on
the decorated method's shape: only device-first methods (``attach``, ``spawn``,
...) pass a real device, so only they can decide ``server_reachable``. For
script-first methods (``create_script``, ``load_script``) the first positional
is a Script/Session, and asserting ``server_reachable=False`` there would point
users at a frida-server problem that does not exist — the field must stay
``None`` ("unknown"). These tests pin that split with mock frida objects.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import frida
import pytest

from friTap.backends.base import (
    BackendError,
    BackendTransportError,
)
from friTap.backends.frida_backend import FridaBackend


def test_backend_error_context_default_server_reachable_is_none():
    # The whole "unknown vs. False" distinction rests on this default.
    from friTap.backends.base import BackendErrorContext
    assert BackendErrorContext().server_reachable is None


def test_load_script_transport_error_leaves_server_reachable_unknown():
    backend = FridaBackend()
    # spec'd to a real Script: it has no query_system_parameters(), which is
    # exactly why probing it as a device used to yield a bogus False.
    script = MagicMock(spec=frida.core.Script)
    script.load.side_effect = frida.TransportError("connection closed")

    with pytest.raises(BackendTransportError) as exc_info:
        backend.load_script(script)

    assert exc_info.value.context.server_reachable is None
    assert exc_info.value.context.server_reachable is not False


def test_create_script_transport_error_leaves_server_reachable_unknown():
    backend = FridaBackend()
    session = MagicMock()
    session.create_script.side_effect = frida.TransportError("connection closed")

    with pytest.raises(BackendTransportError) as exc_info:
        backend.create_script(session, "// a very large agent source")

    assert exc_info.value.context.server_reachable is None


def test_get_device_transport_error_leaves_server_reachable_unknown():
    # get_device's first positional is a selector (bool / device id), not a
    # device object, so it is non-device-first too.
    backend = FridaBackend()

    with patch.object(frida, "get_device", side_effect=frida.TransportError("no route")):
        with pytest.raises(BackendTransportError) as exc_info:
            backend.get_device("emulator-5554")

    assert exc_info.value.context.server_reachable is None


def test_device_first_method_still_collects_device_context():
    # attach() is device-first: a healthy mock device answers
    # query_system_parameters(), so server_reachable must be a real bool.
    backend = FridaBackend()
    device = MagicMock()
    device.attach.side_effect = frida.TransportError("connection closed")

    with pytest.raises(BackendTransportError) as exc_info:
        backend.attach(device, "com.example.app")

    ctx = exc_info.value.context
    assert isinstance(ctx.server_reachable, bool)
    assert ctx.server_reachable is True
    device.query_system_parameters.assert_called_once_with()


def test_script_first_method_keeps_category_and_original_exception():
    backend = FridaBackend()
    script = MagicMock()
    original = frida.TransportError("connection closed")
    script.load.side_effect = original

    with pytest.raises(BackendTransportError) as exc_info:
        backend.load_script(script)

    assert exc_info.value.category == "frida_transport"
    assert exc_info.value.original_exception is original


def test_script_first_non_frida_exception_is_tagged_backend_bug():
    backend = FridaBackend()
    script = MagicMock()
    original = ValueError("not a frida error")
    script.load.side_effect = original

    with pytest.raises(BackendError) as exc_info:
        backend.load_script(script)

    assert not isinstance(exc_info.value, BackendTransportError)
    assert exc_info.value.category == "backend_bug"
    assert exc_info.value.original_exception is original
    assert "load_script" in str(exc_info.value)


def test_wrapper_preserves_function_metadata():
    # functools.wraps must survive the extra decorator layer, for both the
    # bare and the parameterised form.
    assert FridaBackend.attach.__name__ == "attach"
    assert FridaBackend.load_script.__name__ == "load_script"
    assert FridaBackend.create_script.__name__ == "create_script"


def test_unload_script_is_not_decorated():
    # Documented on purpose: unload_script swallows its own exceptions (best
    # effort cleanup) and carries no @_wrap_frida_errors, so there is no
    # context to assert on. If it ever gains the decorator, annotate it
    # first_arg_is_device=False and extend these tests.
    backend = FridaBackend()
    script = MagicMock()
    script.unload.side_effect = frida.TransportError("connection closed")
    assert backend.unload_script(script) is None
