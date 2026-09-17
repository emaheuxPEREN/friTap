#!/usr/bin/env python3

"""Backward-compatibility shim. New code should use CoreController + Session.

    from friTap import CoreController, Session, FriTapConfig  # recommended
    from friTap import SSL_Logger  # legacy (delegates to friTap.legacy)
"""
# Re-exposed for tests that still patch ``friTap.ssl_logger.frida`` /
# ``friTap.ssl_logger.logging``. The legacy core module imports both for
# its own use; we mirror them here so unittest.mock.patch can target them
# at the documented entry-point path. Removing these breaks every test
# that uses ``patch("friTap.ssl_logger.frida.X")``.
import logging

import frida

from .constants import SSL_READ, SSL_WRITE, ContentType
from .legacy.ssl_logger_core import SSL_Logger, _PluginSessionShim, get_addr_string

__all__ = ["SSL_Logger", "SSL_READ", "SSL_WRITE", "ContentType", "get_addr_string", "_PluginSessionShim", "frida", "logging"]
